import os
import sys
import json
import time
import re
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

PAGES_TO_LOAD = int(os.environ.get("FOOTSCAN_PAGES_TO_LOAD", "2"))
INITIAL_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_INITIAL_MATCHES_PER_TEAM", "15"))
SECOND_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_SECOND_MATCHES_PER_TEAM", "17"))
MAX_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_MAX_MATCHES_PER_TEAM", "20"))
INCIDENT_BATCH_SIZE = int(os.environ.get("FOOTSCAN_INCIDENT_BATCH_SIZE", "4"))

POSITIVE_VALUES = {
    "goal": 1,
    "goalWithAssist": 1.5,
    "assist": 0.5,
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


def signed_attack_value(kind, is_for_analyzed_team):
    base = POSITIVE_VALUES.get(kind, 0)
    return base if is_for_analyzed_team else -base


def signed_card_value(kind, is_for_analyzed_team):
    base = CARD_VALUES_FOR_TEAM.get(kind, 0)
    return base if is_for_analyzed_team else -base


def parse_incidents(incidents, match, analyzed_team_id):
    events = []
    match_label = make_match_label(match)
    match_id = match.get("id")

    for inc in incidents:
        if not isinstance(inc, dict):
            continue

        minute = inc.get("time")
        added = inc.get("addedTime") or 0

        if minute is None or minute < 1 or minute > 90:
            continue

        minute_label = f"{minute}+{added}'" if added else f"{minute}'"
        is_for_team = incident_belongs_to_analyzed_team(inc, match, analyzed_team_id)
        camp_label = "Équipe analysée" if is_for_team else "Adversaire"
        side = "team" if is_for_team else "opponent"

        if inc.get("incidentType") == "goal":
            player = inc.get("player") or {}
            assist1 = inc.get("assist1") or None
            scorer = player.get("name") or "—"
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

                events.append({
                    "type": "assist",
                    "value": signed_attack_value("assist", is_for_team),
                    "minute": minute,
                    "added": added,
                    "minuteLabel": minute_label,
                    "match": match_label,
                    "matchId": match_id,
                    "side": side,
                    "detail": f"{camp_label} · {assister} → {scorer}",
                    "icon": "🅰️",
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

        if inc.get("incidentType") == "card":
            player = inc.get("player") or {}

            if not player.get("id"):
                continue

            cls = inc.get("incidentClass")
            player_name = player.get("name") or "—"

            if cls == "yellow":
                events.append({
                    "type": "yellow",
                    "value": signed_card_value("yellow", is_for_team),
                    "minute": minute,
                    "added": added,
                    "minuteLabel": minute_label,
                    "match": match_label,
                    "matchId": match_id,
                    "side": side,
                    "detail": f"{camp_label} · {player_name}",
                    "icon": "🟨",
                })

            elif cls == "yellowRed":
                events.append({
                    "type": "secondYellow",
                    "value": signed_card_value("secondYellow", is_for_team),
                    "minute": minute,
                    "added": added,
                    "minuteLabel": minute_label,
                    "match": match_label,
                    "matchId": match_id,
                    "side": side,
                    "detail": f"{camp_label} · {player_name}",
                    "icon": "🟧",
                })

                events.append({
                    "type": "redFromSecondYellow",
                    "value": signed_card_value("redFromSecondYellow", is_for_team),
                    "minute": minute,
                    "added": added,
                    "minuteLabel": minute_label,
                    "match": match_label,
                    "matchId": match_id,
                    "side": side,
                    "detail": f"{camp_label} · {player_name}",
                    "icon": "🟥",
                })

            elif cls == "red":
                events.append({
                    "type": "red",
                    "value": signed_card_value("red", is_for_team),
                    "minute": minute,
                    "added": added,
                    "minuteLabel": minute_label,
                    "match": match_label,
                    "matchId": match_id,
                    "side": side,
                    "detail": f"{camp_label} · {player_name}",
                    "icon": "🟥",
                })

    def sort_key(ev):
        time_value = ev.get("minute", 0) + (ev.get("added", 0) or 0) / 100
        order = {
            "goalWithAssist": 0,
            "goal": 0,
            "assist": 1,
            "secondYellow": 2,
            "redFromSecondYellow": 3,
            "yellow": 4,
            "red": 4,
        }.get(ev.get("type"), 9)
        return (-time_value, order)

    events.sort(key=sort_key)
    return events


def value_at_rank(events, rank):
    if not rank or rank < 1:
        return {"value": None, "sources": []}

    rank = float(rank)
    base_rank = int(rank)
    fraction = round(rank - base_rank, 10)

    lower_index = base_rank - 1
    upper_index = lower_index + 1

    if lower_index < 0 or lower_index >= len(events):
        return {"value": None, "sources": []}

    if abs(fraction) < 0.0000001:
        source = dict(events[lower_index])
        source["rankIndex"] = base_rank
        source["weight"] = 1

        return {
            "value": round(source["value"], 4),
            "sources": [source],
        }

    if upper_index >= len(events):
        return {"value": None, "sources": []}

    lower_weight = 1 - fraction
    upper_weight = fraction

    lower_source = dict(events[lower_index])
    upper_source = dict(events[upper_index])

    lower_source["rankIndex"] = base_rank
    lower_source["weight"] = round(lower_weight, 4)

    upper_source["rankIndex"] = base_rank + 1
    upper_source["weight"] = round(upper_weight, 4)

    value = (
        lower_source["value"] * lower_weight +
        upper_source["value"] * upper_weight
    )

    return {
        "value": round(value, 4),
        "sources": [lower_source, upper_source],
    }


def range_stats_between_ranks(events, rank1, rank2):
    if not events or not rank1 or not rank2:
        return None

    try:
        low_rank = float(min(rank1, rank2))
        high_rank = float(max(rank1, rank2))
    except Exception:
        return None

    if low_rank < 1 or high_rank < 1:
        return None

    def floor_rank(value):
        return int(value)

    def ceil_rank(value):
        base = int(value)
        fraction = round(value - base, 10)
        return base if abs(fraction) < 0.0000001 else base + 1

    start_rank = floor_rank(low_rank)
    end_rank = ceil_rank(high_rank)

    start_index = max(0, start_rank - 1)
    end_index = min(len(events) - 1, end_rank - 1)

    if start_index > end_index or start_index >= len(events):
        return None

    selected = events[start_index:end_index + 1]

    values = []

    for event in selected:
        try:
            values.append(round(float(event.get("value", 0)), 4))
        except Exception:
            continue

    if not values:
        return None

    average = round(sum(values) / len(values), 4)

    counts = {}

    for value in values:
        counts[value] = counts.get(value, 0) + 1

    max_count = max(counts.values())
    modes = [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        if count == max_count
    ]

    return {
        "startRank": start_rank,
        "endRank": end_rank,
        "requestedStartRank": round(low_rank, 4),
        "requestedEndRank": round(high_rank, 4),
        "count": len(values),
        "average": average,
        "modes": modes,
    }


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
        if len(all_events) >= max_needed:
            break

        update_scan_job(
            job_id,
            status="running",
            message=(
                f"{team_name} · scan progressif jusqu’à {stage_limit} matchs\n"
                f"Événements trouvés : {len(all_events)}/{max_needed}"
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
                    f"Événements trouvés : {len(all_events)}/{max_needed}"
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

                if len(all_events) >= max_needed:
                    break

            scanned_until = batch_end

            if len(all_events) >= max_needed:
                break

    update_scan_job(
        job_id,
        status="running",
        message=f"{team_name} · terminé ({len(all_events)} événements, {len(matches_used)} matchs).",
        progress=base_progress + progress_span,
    )

    return {
        "events": all_events,
        "matchesUsed": matches_used,
    }


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

    ranks = [rank1]

    if rank2 is not None:
        ranks.append(rank2)

    max_needed = int(max(ranks) + 0.999999)

    print(f"Scan complet: job={job_id} match={match_id} ranks={ranks}")

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
            max_needed,
            home_team.get("name") or "Domicile",
            12,
            40,
        )

        away_scan = scan_team(
            job_id,
            away_team["id"],
            skip_away,
            max_needed,
            away_team.get("name") or "Extérieur",
            54,
            40,
        )

        home = {
            **home_team,
            **home_scan,
            "r1": value_at_rank(home_scan["events"], rank1),
            "r2": value_at_rank(home_scan["events"], rank2) if rank2 else None,
            "rangeStats": range_stats_between_ranks(home_scan["events"], rank1, rank2) if rank2 else None,
        }

        away = {
            **away_team,
            **away_scan,
            "r1": value_at_rank(away_scan["events"], rank1),
            "r2": value_at_rank(away_scan["events"], rank2) if rank2 else None,
            "rangeStats": range_stats_between_ranks(away_scan["events"], rank1, rank2) if rank2 else None,
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
            "rank1": rank1,
            "rank2": rank2,
            "config": {
                "pagesToLoad": PAGES_TO_LOAD,
                "initialMatchesPerTeam": INITIAL_MATCHES_PER_TEAM,
                "secondMatchesPerTeam": SECOND_MATCHES_PER_TEAM,
                "maxMatchesPerTeam": MAX_MATCHES_PER_TEAM,
                "incidentBatchSize": INCIDENT_BATCH_SIZE,
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
    print("Pages SofaScore: 2 pages activées.")
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
