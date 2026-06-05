import os
import sys
import json
import time
import re
import math
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed


RAW_QUEUE_KEY = "sofa:queue"
RAW_PREFETCH_QUEUE_KEY = "sofa:prefetch_queue"
SCAN_QUEUE_KEY = "footscan:scan:queue"

CACHE_PREFIX = "sofa:cache:"
ERROR_PREFIX = "sofa:error:"
REQUEST_PREFIX = "sofa:req:"
LOCK_PREFIX = "sofa:lock:"
PREFETCH_LOCK_PREFIX = "sofa:prefetch_lock:"
SCAN_JOB_PREFIX = "footscan:scan:job:"

CACHE_TTL_SECONDS = int(os.environ.get("SOFA_CACHE_TTL_SECONDS", "86400"))
ERROR_TTL_SECONDS = int(os.environ.get("SOFA_ERROR_TTL_SECONDS", "60"))
SCAN_JOB_TTL_SECONDS = int(os.environ.get("SCAN_JOB_TTL_SECONDS", "86400"))
SLEEP_SECONDS = float(os.environ.get("WORKER_SLEEP_SECONDS", "0.5"))
PREFETCH_MAX_MATCHES_PER_PAGE = int(os.environ.get("PREFETCH_MAX_MATCHES_PER_PAGE", "17"))

PAGES_TO_LOAD = int(os.environ.get("FOOTSCAN_PAGES_TO_LOAD", "10"))
INITIAL_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_INITIAL_MATCHES_PER_TEAM", "15"))
SECOND_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_SECOND_MATCHES_PER_TEAM", "17"))
MAX_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_MAX_MATCHES_PER_TEAM", "20"))
INCIDENT_BATCH_SIZE = int(os.environ.get("FOOTSCAN_INCIDENT_BATCH_SIZE", "4"))
RANK_EVENT_STEP = 7.25 / 8

POSITIVE_VALUES = {
    "goal": 1,
    "goalWithAssist": 1.5,
    "assist": 0.5,
}

NEGATIVE_VALUES_FOR_TEAM = {
    "ownGoal": -1,
}

CARD_VALUES_FOR_TEAM = {
    "yellow": -0.25,
    "secondYellow": -0.5,
    "red": -1,
    "redFromSecondYellow": -1.5,
}

LABELS = {
    "goal": "But",
    "goalWithAssist": "But + passe",
    "assist": "Passe décisive",
    "yellow": "Jaune",
    "secondYellow": "Deuxième jaune",
    "red": "Rouge direct",
    "redFromSecondYellow": "Rouge via 2e jaune",
    "ownGoal": "But contre son camp",
}


def env(name):
    value = os.environ.get(name)

    if not value:
        raise RuntimeError(f"Variable d'environnement manquante: {name}")

    return value


UPSTASH_URL = env("UPSTASH_REDIS_REST_URL")
UPSTASH_TOKEN = env("UPSTASH_REDIS_REST_TOKEN")


def redis_cmd(*cmd):
    req = urllib.request.Request(
        UPSTASH_URL,
        data=json.dumps(list(cmd)).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {UPSTASH_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="replace")

    data = json.loads(raw)

    if data.get("error"):
        raise RuntimeError(f"Upstash error: {data['error']}")

    return data.get("result")


def read_url(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            return status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body


def validate_json(status, body, path, source):
    if status != 200:
        return None, f"{source}: HTTP {status} sur {path}: {body[:300]}"

    text = body.strip()

    if not text:
        return None, f"{source}: réponse vide sur {path}"

    if text.startswith("<"):
        return None, f"{source}: HTML reçu au lieu de JSON sur {path}: {text[:300]}"

    try:
        data = json.loads(text)
    except Exception:
        return None, f"{source}: JSON invalide sur {path}: {text[:300]}"

    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return None, f"{source}: erreur SofaScore sur {path}: {data['error']}"

    return body, None


def sofa_fetch(path):
    clean_path = path.lstrip("/")

    urls = [
        f"https://www.sofascore.com/api/v1/{clean_path}",
        f"https://api.sofascore.com/api/v1/{clean_path}",
    ]

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        "Referer": "https://www.sofascore.com/",
        "Origin": "https://www.sofascore.com",
    }

    last_error = None

    for url in urls:
        status, body = read_url(url, headers)
        valid_body, error = validate_json(status, body, clean_path, url)

        if valid_body is not None:
            return valid_body

        last_error = error
        print(f"Échec: {error}", file=sys.stderr)

    raise RuntimeError(last_error or f"Impossible de récupérer {clean_path}")


def cache_key(path):
    return f"{CACHE_PREFIX}{path.lstrip('/')}"


def error_key(path):
    return f"{ERROR_PREFIX}{path.lstrip('/')}"


def get_cached_body(path):
    return redis_cmd("GET", cache_key(path))


def is_cached(path):
    return bool(get_cached_body(path))


def set_cache(path, body):
    redis_cmd("SET", cache_key(path), body, "EX", str(CACHE_TTL_SECONDS))


def set_error(path, error_message):
    payload = {
        "error": error_message,
        "path": path,
        "source": "local_worker",
    }

    redis_cmd("SET", error_key(path), json.dumps(payload), "EX", str(ERROR_TTL_SECONDS))


def get_json(path):
    clean_path = path.lstrip("/")
    cached = get_cached_body(clean_path)

    if cached:
        return json.loads(cached)

    body = sofa_fetch(clean_path)
    set_cache(clean_path, body)
    maybe_enqueue_incidents_from_team_page(clean_path, body)
    return json.loads(body)


def extract_events_from_body(body):
    try:
        data = json.loads(body)
    except Exception:
        return []

    if isinstance(data, dict):
        events = data.get("events", [])
    elif isinstance(data, list):
        events = data
    else:
        events = []

    if not isinstance(events, list):
        return []

    return events


def enqueue_prefetch(path):
    clean_path = path.lstrip("/")
    lock_key = f"{PREFETCH_LOCK_PREFIX}{clean_path}"

    if is_cached(clean_path):
        return False

    lock_result = redis_cmd(
        "SET",
        lock_key,
        "1",
        "EX",
        "600",
        "NX",
    )

    if lock_result == "OK":
        redis_cmd("LPUSH", RAW_PREFETCH_QUEUE_KEY, clean_path)
        return True

    return False


def maybe_enqueue_incidents_from_team_page(path, body):
    clean_path = path.lstrip("/")

    if not re.match(r"^team/\d+/events/last/\d+$", clean_path):
        return

    events = extract_events_from_body(body)
    finished = []

    for match in events:
        if not isinstance(match, dict):
            continue

        if (match.get("status") or {}).get("type") != "finished":
            continue

        match_id = match.get("id")

        if not match_id:
            continue

        start_timestamp = match.get("startTimestamp") or 0

        finished.append({
            "id": match_id,
            "startTimestamp": start_timestamp,
        })

    finished.sort(key=lambda x: x["startTimestamp"], reverse=True)

    count = 0

    for match in finished[:PREFETCH_MAX_MATCHES_PER_PAGE]:
        incident_path = f"event/{match['id']}/incidents"

        if enqueue_prefetch(incident_path):
            count += 1

    if count:
        print(f"Préchargement incidents ajouté: {count} match(s) depuis {clean_path}")


def now_ts():
    return int(time.time())


def update_scan_job(job_id, **fields):
    key = f"{SCAN_JOB_PREFIX}{job_id}"
    raw = redis_cmd("GET", key)

    if raw:
        job = json.loads(raw)
    else:
        job = {"id": job_id}

    job.update(fields)
    job["updatedAt"] = now_ts()

    redis_cmd("SET", key, json.dumps(job, ensure_ascii=False), "EX", str(SCAN_JOB_TTL_SECONDS))
    return job


def format_date(timestamp):
    if not timestamp:
        return ""

    return time.strftime("%d.%m.%y", time.localtime(int(timestamp)))


def get_competition_name(match):
    tournament = match.get("tournament") or {}
    unique_from_tournament = tournament.get("uniqueTournament") or {}
    unique = match.get("uniqueTournament") or {}
    season = match.get("season") or {}

    return (
        unique_from_tournament.get("name") or
        unique.get("name") or
        tournament.get("name") or
        season.get("name") or
        ""
    )


def make_match_label(match):
    date = format_date(match.get("startTimestamp"))
    competition = get_competition_name(match)
    prefix = " · ".join([x for x in [date, competition] if x])

    home = (match.get("homeTeam") or {}).get("name") or "?"
    away = (match.get("awayTeam") or {}).get("name") or "?"
    home_score = (match.get("homeScore") or {}).get("current", "-")
    away_score = (match.get("awayScore") or {}).get("current", "-")
    teams = f"{home} {home_score}-{away_score} {away}"

    return f"{prefix} · {teams}" if prefix else teams


def incident_belongs_to_analyzed_team(incident, match, analyzed_team_id):
    home_team = match.get("homeTeam") or {}
    team_is_home = home_team.get("id") == analyzed_team_id

    if isinstance(incident.get("isHome"), bool):
        return incident.get("isHome") == team_is_home

    direct_team_id = (
        (incident.get("team") or {}).get("id") or
        (incident.get("playerTeam") or {}).get("id") or
        ((incident.get("player") or {}).get("team") or {}).get("id")
    )

    if direct_team_id:
        return direct_team_id == analyzed_team_id

    return True


def is_own_goal_incident(incident):
    cls = str(incident.get("incidentClass") or "").lower()

    return (
        incident.get("isOwnGoal") is True or
        incident.get("ownGoal") is True or
        cls in {"owngoal", "own_goal", "own goal"} or
        "own" in cls
    )


def own_goal_committed_by_analyzed_team(incident, match, analyzed_team_id):
    player = incident.get("player") or {}

    # Pour un CSC, SofaScore peut comptabiliser le but pour l'équipe bénéficiaire.
    # Dans notre méthode, on veut toujours attribuer l'événement au joueur/club
    # qui marque contre son camp. On privilégie donc l'équipe du joueur.
    player_team_id = (
        ((incident.get("playerTeam") or {}).get("id")) or
        ((player.get("team") or {}).get("id"))
    )

    if player_team_id:
        return player_team_id == analyzed_team_id

    # Repli: si SofaScore place isHome du côté bénéficiaire du but,
    # l'équipe qui marque contre son camp est l'autre côté.
    if isinstance(incident.get("isHome"), bool):
        home_team = match.get("homeTeam") or {}
        analyzed_is_home = home_team.get("id") == analyzed_team_id
        own_goal_team_is_home = not incident.get("isHome")
        return own_goal_team_is_home == analyzed_is_home

    return incident_belongs_to_analyzed_team(incident, match, analyzed_team_id)


def signed_attack_value(kind, is_for_analyzed_team):
    base = POSITIVE_VALUES.get(kind, 0)
    return base if is_for_analyzed_team else -base


def signed_card_value(kind, is_for_analyzed_team):
    base = CARD_VALUES_FOR_TEAM.get(kind, 0)
    return base if is_for_analyzed_team else -base


def signed_own_goal_value(is_for_analyzed_team):
    base = NEGATIVE_VALUES_FOR_TEAM["ownGoal"]
    return base if is_for_analyzed_team else -base


def parse_incidents(incidents, match, analyzed_team_id):
    """Récupère uniquement les buts.

    Depuis cette version, les cartons et les passes décisives seules ne sont
    plus parcourus. Les seuls événements conservés sont :
    - but sans passe
    - but avec passe
    - but contre son camp
    """
    events = []
    match_label = make_match_label(match)
    match_id = match.get("id")

    for inc in incidents:
        if not isinstance(inc, dict):
            continue

        if inc.get("incidentType") != "goal":
            continue

        minute = inc.get("time")
        added = inc.get("addedTime") or 0

        if minute is None or minute < 1 or minute > 90:
            continue

        minute_label = f"{minute}+{added}'" if added else f"{minute}'"
        is_for_team = incident_belongs_to_analyzed_team(inc, match, analyzed_team_id)
        camp_label = "Équipe analysée" if is_for_team else "Adversaire"
        side = "team" if is_for_team else "opponent"

        player = inc.get("player") or {}
        scorer = player.get("name") or "—"

        if is_own_goal_incident(inc):
            is_for_team = own_goal_committed_by_analyzed_team(inc, match, analyzed_team_id)
            camp_label = "Équipe analysée" if is_for_team else "Adversaire"
            side = "team" if is_for_team else "opponent"

            events.append({
                "type": "ownGoal",
                "value": signed_own_goal_value(is_for_team),
                "minute": minute,
                "added": added,
                "minuteLabel": minute_label,
                "match": match_label,
                "matchId": match_id,
                "side": side,
                "detail": f"{camp_label} · CSC · {scorer}",
                "icon": "🥅",
            })
            continue

        assist1 = inc.get("assist1") or None
        assister = assist1.get("name") if isinstance(assist1, dict) else None

        if assister:
            events.append({
                "type": "goalWithAssist",
                "value": signed_attack_value("goalWithAssist", is_for_team),
                "minute": minute,
                "added": added,
                "minuteLabel": minute_label,
                "match": match_label,
                "matchId": match_id,
                "side": side,
                "detail": f"{camp_label} · {scorer} — passe : {assister}",
                "icon": "⚽",
            })
        else:
            events.append({
                "type": "goal",
                "value": signed_attack_value("goal", is_for_team),
                "minute": minute,
                "added": added,
                "minuteLabel": minute_label,
                "match": match_label,
                "matchId": match_id,
                "side": side,
                "detail": f"{camp_label} · {scorer}",
                "icon": "⚽",
            })

    def sort_key(ev):
        time_value = ev.get("minute", 0) + (ev.get("added", 0) or 0) / 100
        order = {
            "goalWithAssist": 0,
            "goal": 0,
            "ownGoal": 0,
        }.get(ev.get("type"), 9)
        return (-time_value, order)

    events.sort(key=sort_key)
    return events


def event_rank_quantity(event):
    """Quantité qui fait avancer le rang.

    Nouvelle logique: chaque événement fait avancer le rang de 7.25 / 8,
    en classique comme en simultané.
    Le barème de performance reste inchangé ; il sert à la valeur récupérée,
    pas à la distance parcourue vers le rang.
    """
    if not isinstance(event, dict):
        return 0.0

    try:
        value = float(event.get("value", 0))
    except Exception:
        return 0.0

    if not math.isfinite(value):
        return 0.0

    return RANK_EVENT_STEP


def total_rank_quantity(events):
    return sum(event_rank_quantity(event) for event in (events or []))


def annotate_rank_source(event, event_index, cumulative_start, cumulative_end, target_rank):
    source = dict(event)
    source["rankIndex"] = event_index + 1
    source["rankQuantity"] = event_rank_quantity(event)
    source["cumulativeStart"] = cumulative_start
    source["cumulativeEnd"] = cumulative_end
    source["rankTarget"] = float(target_rank)
    source["weight"] = 1
    source["rankMode"] = "quantity"
    return source


def value_at_rank(events, rank):
    """Performance exacte au rang demandé.

    Important: le rang n'est plus arrondi ni ramené au dernier .0/.5.
    Chaque événement avance de RANK_EVENT_STEP (7.25/8). On convertit donc
    le rang demandé en position exacte dans la liste d'événements, puis on
    interpole entre les deux événements autour de cette position.

    Exemple avec RANK_EVENT_STEP = 0.90625:
    - rang = 30.0000  -> position événement = 33.103448...
    - résultat = 89.6552% de l'événement #33 + 10.3448% de l'événement #34

    Ainsi, la performance finale peut être une valeur exacte comme 0.1379,
    et plus seulement une valeur brute du barème (-1, -0.5, 0, +0.5, +1...).
    """
    if rank is None or rank <= 0:
        return {"value": None, "sources": [], "rankMode": "quantity_exact"}

    try:
        target_rank = float(rank)
    except Exception:
        return {"value": None, "sources": [], "rankMode": "quantity_exact"}

    if target_rank <= 0:
        return {"value": None, "sources": [], "rankMode": "quantity_exact"}

    clean_events = [event for event in (events or []) if event_rank_quantity(event) > 0]

    if not clean_events:
        return {
            "value": None,
            "sources": [],
            "rankMode": "quantity_exact",
            "targetRank": target_rank,
            "totalQuantity": 0,
        }

    step = RANK_EVENT_STEP
    total_quantity = len(clean_events) * step

    if target_rank > total_quantity + 1e-9:
        return {
            "value": None,
            "sources": [],
            "rankMode": "quantity_exact",
            "targetRank": target_rank,
            "totalQuantity": round(total_quantity, 6),
        }

    exact_position = target_rank / step

    # Si le rang tombe exactement sur la borne d'un événement, on prend cet événement.
    nearest_integer = round(exact_position)

    if nearest_integer >= 1 and abs(exact_position - nearest_integer) < 1e-9:
        event_index = int(nearest_integer) - 1

        if event_index < 0 or event_index >= len(clean_events):
            return {
                "value": None,
                "sources": [],
                "rankMode": "quantity_exact",
                "targetRank": target_rank,
                "exactPosition": exact_position,
                "totalQuantity": round(total_quantity, 6),
            }

        cumulative_start = event_index * step
        cumulative_end = cumulative_start + step
        source = annotate_rank_source(clean_events[event_index], event_index, cumulative_start, cumulative_end, target_rank)
        source["rankIndexExact"] = exact_position
        source["exactPosition"] = exact_position
        source["weight"] = 1

        return {
            "value": float(source.get("value", 0)),
            "sources": [source],
            "rankMode": "quantity_exact",
            "targetRank": target_rank,
            "exactPosition": exact_position,
            "totalQuantity": round(total_quantity, 6),
        }

    lower_rank_index = math.floor(exact_position)
    fraction = exact_position - lower_rank_index

    # Si la position est avant le premier événement complet, on utilise le premier événement.
    if lower_rank_index < 1:
        source = annotate_rank_source(clean_events[0], 0, 0, step, target_rank)
        source["rankIndexExact"] = exact_position
        source["exactPosition"] = exact_position
        source["weight"] = 1

        return {
            "value": float(source.get("value", 0)),
            "sources": [source],
            "rankMode": "quantity_exact",
            "targetRank": target_rank,
            "exactPosition": exact_position,
            "totalQuantity": round(total_quantity, 6),
        }

    lower_index = lower_rank_index - 1
    upper_index = lower_rank_index

    if lower_index < 0 or upper_index >= len(clean_events):
        return {
            "value": None,
            "sources": [],
            "rankMode": "quantity_exact",
            "targetRank": target_rank,
            "exactPosition": exact_position,
            "totalQuantity": round(total_quantity, 6),
        }

    lower_weight = 1 - fraction
    upper_weight = fraction

    lower_start = lower_index * step
    lower_end = lower_start + step
    upper_start = upper_index * step
    upper_end = upper_start + step

    lower_source = annotate_rank_source(clean_events[lower_index], lower_index, lower_start, lower_end, target_rank)
    upper_source = annotate_rank_source(clean_events[upper_index], upper_index, upper_start, upper_end, target_rank)

    lower_source["rankIndexExact"] = exact_position
    lower_source["exactPosition"] = exact_position
    lower_source["weight"] = round(lower_weight, 8)

    upper_source["rankIndexExact"] = exact_position
    upper_source["exactPosition"] = exact_position
    upper_source["weight"] = round(upper_weight, 8)

    value = (
        float(lower_source.get("value", 0)) * lower_weight +
        float(upper_source.get("value", 0)) * upper_weight
    )

    return {
        "value": float(value),
        "sources": [lower_source, upper_source],
        "rankMode": "quantity_exact",
        "targetRank": target_rank,
        "exactPosition": exact_position,
        "totalQuantity": round(total_quantity, 6),
    }

def event_intersects_rank_zone(cumulative_start, cumulative_end, low_rank, high_rank):
    # Chaque événement couvre (start, end]. Il est dans la zone s'il touche
    # le rang bas ou s'il commence strictement avant le rang haut.
    if high_rank < low_rank:
        low_rank, high_rank = high_rank, low_rank

    return cumulative_end >= low_rank - 1e-9 and cumulative_start < high_rank - 1e-9


def events_between_rank_quantities(events, rank1, rank2=None):
    if not events or not rank1:
        return [], None, None, 0.0

    try:
        first_rank = float(rank1)
        second_rank = float(rank2) if rank2 is not None else first_rank
    except Exception:
        return [], None, None, 0.0

    low_rank = min(first_rank, second_rank)
    high_rank = max(first_rank, second_rank)

    cumulative = 0.0
    selected = []

    for event_index, event in enumerate(events or []):
        quantity = event_rank_quantity(event)

        if quantity <= 0:
            continue

        cumulative_start = cumulative
        cumulative_end = cumulative + quantity

        if event_intersects_rank_zone(cumulative_start, cumulative_end, low_rank, high_rank):
            selected.append(annotate_rank_source(event, event_index, cumulative_start, cumulative_end, low_rank))

        cumulative = cumulative_end

        if cumulative_start > high_rank + 1e-9:
            break

    return selected, round(low_rank, 4), round(high_rank, 4), round(sum(event_rank_quantity(event) for event in selected), 4)


def zone_stats_between_ranks(events, rank1, rank2=None, group_mode="target"):
    """Calcule les stats entre deux rangs, rangs finaux inclus.

    Nouvelle logique: chaque événement fait avancer le rang de 7.25 / 8, peu importe sa valeur de barème.

    group_mode="target" : groupe par événement + équipe attribuée + valeur.
      -> utile pour une zone d'équipe.
    group_mode="global" : groupe seulement par événement + valeur.
      -> utile pour la zone collective simultanée, qui n'appartient à aucun camp.
    """
    empty = {
        "average": None,
        "modeValues": [],
        "modeItems": [],
        "modeCount": 0,
        "count": 0,
        "startRankIndex": None,
        "endRankIndex": None,
        "totalQuantity": 0,
        "rankMode": "quantity",
        "groupMode": group_mode,
    }

    selected_events, start_rank_value, end_rank_value, selected_quantity = events_between_rank_quantities(events, rank1, rank2)

    if not selected_events:
        result = dict(empty)
        result["startRankIndex"] = start_rank_value
        result["endRankIndex"] = end_rank_value
        return result

    values = []
    counts = {}
    examples = {}

    def fallback_target_label(event):
        display_side = event.get("displaySide")

        if display_side:
            text = str(display_side)
            for prefix in ["Attribué à ", "Performance "]:
                if text.startswith(prefix):
                    return text[len(prefix):]
            return text

        return "Équipe analysée" if event.get("side") == "team" else "Adversaire"

    def target_label(event):
        return event.get("targetName") or fallback_target_label(event)

    def origin_label(event):
        if event.get("originLabel"):
            return event.get("originLabel")

        if event.get("linkedFromOpponentPast"):
            return "adversaire passé"

        return "passé direct"

    for event in selected_events:
        try:
            value = round(float(event.get("value", 0)), 4)
        except Exception:
            continue

        values.append(value)

        event_type = event.get("type") or "unknown"
        target = target_label(event)
        origin = origin_label(event)

        if group_mode == "global":
            key = f"{event_type}|{value:.4f}"
        else:
            key = f"{event_type}|{target}|{value:.4f}"

        counts[key] = counts.get(key, 0) + 1

        if key not in examples:
            examples[key] = {
                "type": event_type,
                "label": LABELS.get(event_type, event_type),
                "targetLabel": target,
                "sideLabel": f"attribué à {target}",
                "value": value,
                "icon": event.get("icon") or "•",
                "origins": {},
                "targets": {},
                "groupMode": group_mode,
                "isGlobal": group_mode == "global",
                "rankMode": "quantity",
            }

        origins = examples[key].setdefault("origins", {})
        origins[origin] = origins.get(origin, 0) + 1

        targets = examples[key].setdefault("targets", {})
        target_bucket = targets.setdefault(target, {"count": 0, "origins": {}})
        target_bucket["count"] += 1
        target_bucket["origins"][origin] = target_bucket["origins"].get(origin, 0) + 1

    if not values:
        result = dict(empty)
        result["startRankIndex"] = start_rank_value
        result["endRankIndex"] = end_rank_value
        return result

    mode_count = max(counts.values())
    mode_items = []

    for key, count in counts.items():
        if count != mode_count:
            continue

        item = dict(examples[key])
        item["count"] = count

        origins_dict = item.get("origins") or {}
        item["origins"] = [
            {"label": label, "count": origin_count}
            for label, origin_count in sorted(
                origins_dict.items(),
                key=lambda pair: (-pair[1], pair[0]),
            )
        ]

        targets_dict = item.get("targets") or {}
        target_breakdown = []

        for label, info in sorted(
            targets_dict.items(),
            key=lambda pair: (-pair[1].get("count", 0), pair[0]),
        ):
            origin_items = [
                {"label": origin_label_value, "count": origin_count}
                for origin_label_value, origin_count in sorted(
                    (info.get("origins") or {}).items(),
                    key=lambda pair: (-pair[1], pair[0]),
                )
            ]
            target_breakdown.append({
                "label": label,
                "count": info.get("count", 0),
                "origins": origin_items,
            })

        item["targetBreakdown"] = target_breakdown
        mode_items.append(item)

    mode_items.sort(key=lambda item: (
        -item.get("count", 0),
        str(item.get("label", "")),
        float(item.get("value", 0)),
        str(item.get("targetLabel", "")),
    ))

    mode_values = sorted({round(float(item["value"]), 4) for item in mode_items})

    return {
        "average": round(sum(values) / len(values), 4),
        "modeValues": mode_values,
        "modeItems": mode_items,
        "modeCount": mode_count,
        "count": len(values),
        "startRankIndex": start_rank_value,
        "endRankIndex": end_rank_value,
        "totalQuantity": round(selected_quantity, 4),
        "rankMode": "quantity",
        "groupMode": group_mode,
    }


def zone_events_between_ranks(events, rank1, rank2=None):
    """Retourne les événements situés entre deux rangs, rangs finaux inclus.

    Nouvelle logique: la zone est basée sur le cumul fixe de 7.25 / 8 par événement, pas sur un rang 1 événement = 1.
    """
    selected_events, start_rank_value, end_rank_value, _selected_quantity = events_between_rank_quantities(events, rank1, rank2)
    return selected_events, start_rank_value, end_rank_value


def simultaneous_overall_zone_stats(combined_events, rank1, rank2=None):
    """Zone collective simultanée générale.

    Pour la moyenne globale uniquement, on parcourt la liste collective complète :
    équipe A + équipe B + adversaire passé de A + adversaire passé de B.

    Nouvelle règle : pour cette moyenne globale uniquement, les rangs de base
    sont multipliés par 2. Les zones par équipe gardent, elles, les rangs
    indiqués sans multiplication.

    Chaque événement fait avancer le rang de 7.25 / 8.
    """
    try:
        used_rank1 = float(rank1) * 2
        used_rank2 = float(rank2) * 2 if rank2 is not None else used_rank1
    except Exception:
        used_rank1 = rank1
        used_rank2 = rank2

    result = zone_stats_between_ranks(combined_events or [], used_rank1, used_rank2, group_mode="global")
    result["globalMethod"] = "combined_all_events_double_ranks_fixed_event_step"
    result["rankMultiplier"] = 2
    result["eventStep"] = RANK_EVENT_STEP
    result["originalRank1"] = rank1
    result["originalRank2"] = rank2
    result["usedRank1"] = used_rank1
    result["usedRank2"] = used_rank2
    result["combinedEventCount"] = len(combined_events or [])
    return result

def scan_team(job_id, analyzed_team_id, skip, max_needed, team_name, base_progress, progress_span):
    update_scan_job(
        job_id,
        status="running",
        message=f"{team_name} · récupération des pages SofaScore…",
        progress=base_progress,
    )

    pages = []

    for page in range(PAGES_TO_LOAD):
        update_scan_job(
            job_id,
            status="running",
            message=f"{team_name} · page {page + 1}/{PAGES_TO_LOAD}",
            progress=base_progress + int(progress_span * 0.10 * ((page + 1) / PAGES_TO_LOAD)),
        )

        data = get_json(f"team/{analyzed_team_id}/events/last/{page}")
        page_events = data.get("events") if isinstance(data, dict) else data

        if isinstance(page_events, list):
            pages.extend(page_events)

    by_id = {}

    for match in pages:
        if not isinstance(match, dict):
            continue

        match_id = match.get("id")

        if not match_id:
            continue

        status_type = (match.get("status") or {}).get("type")
        home_id = (match.get("homeTeam") or {}).get("id")
        away_id = (match.get("awayTeam") or {}).get("id")

        if status_type != "finished":
            continue

        if home_id != analyzed_team_id and away_id != analyzed_team_id:
            continue

        by_id[match_id] = match

    sorted_matches = sorted(
        by_id.values(),
        key=lambda m: m.get("startTimestamp") or 0,
        reverse=True,
    )

    selected_matches = sorted_matches[skip:skip + MAX_MATCHES_PER_TEAM]
    stages = []

    for limit in [INITIAL_MATCHES_PER_TEAM, SECOND_MATCHES_PER_TEAM, MAX_MATCHES_PER_TEAM]:
        limit = max(1, min(limit, len(selected_matches)))
        if limit not in stages:
            stages.append(limit)

    all_events = []
    matches_used = []
    scanned_until = 0

    for stage_limit in stages:
        if total_rank_quantity(all_events) >= max_needed:
            break

        update_scan_job(
            job_id,
            status="running",
            message=(
                f"{team_name} · scan progressif jusqu’à {stage_limit} matchs\n"
                f"Avancement trouvé : {round(total_rank_quantity(all_events), 2)}/{max_needed}"
            ),
            progress=base_progress + int(progress_span * 0.13),
        )

        for start in range(scanned_until, stage_limit, INCIDENT_BATCH_SIZE):
            batch = selected_matches[start:min(start + INCIDENT_BATCH_SIZE, stage_limit)]
            batch_end = min(start + len(batch), stage_limit)

            stage_position = batch_end / max(1, MAX_MATCHES_PER_TEAM)

            update_scan_job(
                job_id,
                status="running",
                message=(
                    f"{team_name} · incidents matchs {start + 1}-{batch_end}/{stage_limit}\n"
                    f"Avancement trouvé : {round(total_rank_quantity(all_events), 2)}/{max_needed}"
                ),
                progress=base_progress + int(progress_span * (0.15 + 0.80 * stage_position)),
            )

            scanned = []

            with ThreadPoolExecutor(max_workers=len(batch) or 1) as executor:
                futures = {}

                for idx, match in enumerate(batch):
                    future = executor.submit(get_json, f"event/{match['id']}/incidents")
                    futures[future] = (idx, match)

                for future in as_completed(futures):
                    idx, match = futures[future]
                    data = future.result()
                    incidents = data.get("incidents") if isinstance(data, dict) else data

                    if not isinstance(incidents, list):
                        incidents = []

                    events = parse_incidents(incidents, match, analyzed_team_id)

                    scanned.append({
                        "idx": idx,
                        "match": match,
                        "events": events,
                        "matchUsed": {
                            "id": match.get("id"),
                            "label": make_match_label(match),
                            "count": len(events),
                            "startTimestamp": match.get("startTimestamp") or 0,
                            "competition": get_competition_name(match),
                        },
                    })

            scanned.sort(key=lambda item: item["idx"])

            for item in scanned:
                all_events.extend(item["events"])
                matches_used.append(item["matchUsed"])

                if total_rank_quantity(all_events) >= max_needed:
                    break

            scanned_until = batch_end

            if total_rank_quantity(all_events) >= max_needed:
                break

    update_scan_job(
        job_id,
        status="running",
        message=f"{team_name} · terminé ({len(all_events)} événements, avancement {round(total_rank_quantity(all_events), 2)}, {len(matches_used)} matchs).",
        progress=base_progress + progress_span,
    )

    return {
        "events": all_events,
        "matchesUsed": matches_used,
    }



def apply_simultaneous_match_minute_order(home_scan, away_scan, home_name="Domicile", away_name="Extérieur"):
    """Construit le mode simultané match par match puis minute par minute.

    Règle importante demandée:
    - les événements de l'équipe analysée restent dans son flux.
    - les événements de l'adversaire dans le passé de A sont transférés au flux de B,
      avec la valeur inversée.
    - les événements de l'adversaire dans le passé de B sont transférés au flux de A,
      avec la valeur inversée.
    """

    def strip_camp_prefix(detail):
        text = str(detail or "")
        for prefix in ["Équipe analysée · ", "Adversaire · "]:
            if text.startswith(prefix):
                return text[len(prefix):]
        return text

    def group_by_match(scan):
        order = []
        grouped = {}

        for match in scan.get("matchesUsed") or []:
            match_id = match.get("id")
            if match_id is None:
                continue
            order.append(match_id)
            grouped.setdefault(match_id, [])

        for event in scan.get("events") or []:
            match_id = event.get("matchId")
            grouped.setdefault(match_id, []).append(event)
            if match_id not in order:
                order.append(match_id)

        return order, grouped

    def copy_for_target(event, target_key, source_name, target_name, linked_from_opponent):
        copied = dict(event)
        clean_detail = strip_camp_prefix(copied.get("detail"))

        copied["targetName"] = target_name
        copied["simultaneousTarget"] = target_key
        copied["displaySide"] = f"Attribué à {target_name}"

        if linked_from_opponent:
            try:
                copied["value"] = round(-float(copied.get("value", 0)), 4)
            except Exception:
                copied["value"] = copied.get("value")

            copied["side"] = "team"
            copied["linkedFromOpponentPast"] = True
            copied["originLabel"] = f"adversaire passé de {source_name}"
            copied["detail"] = f"Attribué à {target_name} · origine: adversaire passé de {source_name} · {clean_detail}"
        else:
            copied["originLabel"] = f"passé direct de {target_name}"
            copied["detail"] = f"Attribué à {target_name} · origine: passé direct · {clean_detail}"

        return copied

    home_order, home_grouped = group_by_match(home_scan)
    away_order, away_grouped = group_by_match(away_scan)

    home_events = []
    away_events = []
    combined_events = []
    shared_index = 0
    max_len = max(len(home_order), len(away_order))

    for match_index in range(max_len):
        items = []

        if match_index < len(home_order):
            for original_index, event in enumerate(home_grouped.get(home_order[match_index], [])):
                items.append(("home", original_index, event))

        if match_index < len(away_order):
            for original_index, event in enumerate(away_grouped.get(away_order[match_index], [])):
                items.append(("away", original_index, event))

        def sort_key(item):
            source_key, original_index, event = item
            minute = event.get("minute") or 0
            added = event.get("added") or 0
            return (-(minute + added / 100), 0 if source_key == "home" else 1, original_index)

        for source_key, original_index, event in sorted(items, key=sort_key):
            shared_index += 1

            if source_key == "home":
                if event.get("side") == "opponent":
                    copied = copy_for_target(event, "away", home_name, away_name, True)
                    copied["simultaneousIndex"] = shared_index
                    copied["simultaneousMatchPair"] = match_index + 1
                    away_events.append(copied)
                    combined_events.append(dict(copied))
                else:
                    copied = copy_for_target(event, "home", home_name, home_name, False)
                    copied["simultaneousIndex"] = shared_index
                    copied["simultaneousMatchPair"] = match_index + 1
                    home_events.append(copied)
                    combined_events.append(dict(copied))
            else:
                if event.get("side") == "opponent":
                    copied = copy_for_target(event, "home", away_name, home_name, True)
                    copied["simultaneousIndex"] = shared_index
                    copied["simultaneousMatchPair"] = match_index + 1
                    home_events.append(copied)
                    combined_events.append(dict(copied))
                else:
                    copied = copy_for_target(event, "away", away_name, away_name, False)
                    copied["simultaneousIndex"] = shared_index
                    copied["simultaneousMatchPair"] = match_index + 1
                    away_events.append(copied)
                    combined_events.append(dict(copied))

    combined_events.sort(key=lambda event: event.get("simultaneousIndex") or 0)

    home_result = dict(home_scan)
    away_result = dict(away_scan)
    home_result["events"] = home_events
    away_result["events"] = away_events
    home_result["simultaneousLinkedMode"] = True
    away_result["simultaneousLinkedMode"] = True

    return home_result, away_result, combined_events

def process_scan_job(job_id):
    raw = redis_cmd("GET", f"{SCAN_JOB_PREFIX}{job_id}")

    if not raw:
        print(f"Scan job absent: {job_id}")
        return

    job = json.loads(raw)
    params = job.get("params") or {}

    match_id = str(params.get("matchId") or "").strip()
    rank1 = float(params.get("rank1"))
    rank2 = params.get("rank2")
    rank2 = float(rank2) if rank2 is not None else None
    skip_home = int(params.get("skipHome") or 0)
    skip_away = int(params.get("skipAway") or 0)
    simultaneous_mode = bool(params.get("simultaneousMode"))

    effective_rank1 = rank1
    effective_rank2 = rank2

    ranks = [effective_rank1]

    if effective_rank2 is not None:
        ranks.append(effective_rank2)

    max_needed = float(max(ranks))

    # En mode simultané, chaque performance attribuée à une équipe est construite
    # avec deux historiques :
    # - le passé direct de cette équipe ;
    # - l'adversaire passé de l'autre équipe.
    #
    # Si on ne récupère que "max_needed" événements bruts par équipe, il peut
    # manquer des événements après réattribution, car tous les événements bruts ne
    # finissent pas dans la même liste attribuée. On récupère donc plus large en
    # simultané, puis on reclasse seulement après.
    scan_fetch_needed = max_needed * 2 if simultaneous_mode else max_needed

    print(
        f"Scan complet: job={job_id} match={match_id} "
        f"ranks demandés={[rank1, rank2]} ranks utilisés={ranks} "
        f"objectif avancement brut={scan_fetch_needed} simultaneous={simultaneous_mode}"
    )

    try:
        update_scan_job(job_id, status="running", message="Récupération du match principal…", progress=5)

        match_data = get_json(f"event/{match_id}")
        match = match_data.get("event") if isinstance(match_data, dict) else match_data

        if not isinstance(match, dict) or not match.get("homeTeam") or not match.get("awayTeam"):
            raise RuntimeError("Format du match principal inattendu")

        home_team = match["homeTeam"]
        away_team = match["awayTeam"]

        update_scan_job(
            job_id,
            status="running",
            message=f"Match trouvé : {home_team.get('name')} vs {away_team.get('name')}",
            progress=10,
        )

        home_scan = scan_team(
            job_id,
            home_team["id"],
            skip_home,
            scan_fetch_needed,
            home_team.get("name") or "Domicile",
            12,
            40,
        )

        away_scan = scan_team(
            job_id,
            away_team["id"],
            skip_away,
            scan_fetch_needed,
            away_team.get("name") or "Extérieur",
            54,
            40,
        )

        simultaneous_combined_events = []

        if simultaneous_mode:
            update_scan_job(
                job_id,
                status="running",
                message="Calcul simultané: reclassement match par match puis minute par minute…",
                progress=96,
            )
            home_scan, away_scan, simultaneous_combined_events = apply_simultaneous_match_minute_order(
                home_scan,
                away_scan,
                home_team.get("name") or "Domicile",
                away_team.get("name") or "Extérieur",
            )

        home = {
            **home_team,
            **home_scan,
            "r1": value_at_rank(home_scan["events"], effective_rank1),
            "r2": value_at_rank(home_scan["events"], effective_rank2) if effective_rank2 else None,
            "zoneStats": zone_stats_between_ranks(home_scan["events"], effective_rank1, effective_rank2),
        }

        away = {
            **away_team,
            **away_scan,
            "r1": value_at_rank(away_scan["events"], effective_rank1),
            "r2": value_at_rank(away_scan["events"], effective_rank2) if effective_rank2 else None,
            "zoneStats": zone_stats_between_ranks(away_scan["events"], effective_rank1, effective_rank2),
        }

        result = {
            "match": {
                "id": match.get("id"),
                "homeTeam": home_team,
                "awayTeam": away_team,
                "startTimestamp": match.get("startTimestamp"),
                "label": make_match_label(match),
            },
            "home": home,
            "away": away,
            "requestedRank1": rank1,
            "requestedRank2": rank2,
            "rank1": effective_rank1,
            "rank2": effective_rank2,
            "simultaneousMode": simultaneous_mode,
            "scanModeLabel": "Simultané lié: mêmes rangs, match par match / minute par minute" if simultaneous_mode else "Standard",
            "overallZoneStats": None,
            "config": {
                "pagesToLoad": PAGES_TO_LOAD,
                "initialMatchesPerTeam": INITIAL_MATCHES_PER_TEAM,
                "secondMatchesPerTeam": SECOND_MATCHES_PER_TEAM,
                "maxMatchesPerTeam": MAX_MATCHES_PER_TEAM,
                "incidentBatchSize": INCIDENT_BATCH_SIZE,
                "zoneMethod": "final_ranks_low_to_high",
            },
        }

        update_scan_job(
            job_id,
            status="done",
            message="Scan terminé.",
            progress=100,
            result=result,
            finishedAt=now_ts(),
        )

        print(f"Scan terminé: {job_id}")

    except Exception as e:
        update_scan_job(
            job_id,
            status="error",
            message="Erreur pendant le scan.",
            progress=100,
            error=str(e),
        )

        print(f"ERREUR scan {job_id}: {e}", file=sys.stderr)


def process_raw_request(request_id):
    request_key = f"{REQUEST_PREFIX}{request_id}"
    raw = redis_cmd("GET", request_key)

    if not raw:
        print(f"Request expirée ou absente: {request_id}")
        return

    payload = json.loads(raw)
    path = payload["path"].lstrip("/")
    lock_key = f"{LOCK_PREFIX}{request_id}"

    if is_cached(path):
        redis_cmd("DEL", request_key)
        redis_cmd("DEL", lock_key)
        print(f"Déjà en cache: {path}")
        return

    print(f"Traitement: {path}")

    try:
        body = sofa_fetch(path)

        set_cache(path, body)
        redis_cmd("DEL", error_key(path))
        redis_cmd("DEL", request_key)
        redis_cmd("DEL", lock_key)

        print(f"OK: {path}")

        maybe_enqueue_incidents_from_team_page(path, body)

    except Exception as e:
        set_error(path, str(e))
        redis_cmd("DEL", lock_key)

        print(f"ERREUR: {path}: {e}", file=sys.stderr)


def process_prefetch_path(path):
    clean_path = path.lstrip("/")

    if is_cached(clean_path):
        print(f"Préchargement ignoré, déjà en cache: {clean_path}")
        return

    print(f"Préchargement: {clean_path}")

    try:
        body = sofa_fetch(clean_path)
        set_cache(clean_path, body)
        print(f"OK préchargé: {clean_path}")

        maybe_enqueue_incidents_from_team_page(clean_path, body)

    except Exception as e:
        print(f"ERREUR préchargement: {clean_path}: {e}", file=sys.stderr)


def main():
    once = "--once" in sys.argv

    print("Foot/Scan worker local démarré.")
    print("Version niveau 1: scan complet côté worker activé.")
    print("Pages SofaScore: 10 pages activées.")
    print("Mode simultané lié: mêmes rangs, match par match, minute par minute.")
    print("Option B: scan progressif 15 → 17 → 20 matchs activé.")
    print("Calcul pondéré: X / X.125 / X.25 / X.375 / X.5 / X.625 / X.75 / X.875 activé.")
    print("Barème cartons: jaune, 2e jaune, rouge direct, rouge via 2e jaune activé.")
    print("Version rapide: préchargement incidents activé.")
    print("Laisse cette fenêtre ouverte pendant que tu utilises l'app.")

    while True:
        scan_job_id = redis_cmd("RPOP", SCAN_QUEUE_KEY)

        if scan_job_id:
            process_scan_job(scan_job_id)
            continue

        request_id = redis_cmd("RPOP", RAW_QUEUE_KEY)

        if request_id:
            process_raw_request(request_id)
            continue

        prefetch_path = redis_cmd("RPOP", RAW_PREFETCH_QUEUE_KEY)

        if prefetch_path:
            process_prefetch_path(prefetch_path)
            continue

        if once:
            print("Aucune requête en attente.")
            break

        time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    main()
