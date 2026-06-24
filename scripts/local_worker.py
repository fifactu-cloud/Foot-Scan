import os
import sys
import json
import time
import re
import math
import urllib.request
import urllib.error
import shutil
import subprocess

# Optionnel : curl_cffi imite l'empreinte TLS de Chrome et contourne
# le 403 "challenge" anti-bot de SofaScore. Installation dans Termux :
#     pip install curl_cffi
try:
    from curl_cffi import requests as cffi_requests
    HAS_CURL_CFFI = True
except Exception:
    cffi_requests = None
    HAS_CURL_CFFI = False
from concurrent.futures import ThreadPoolExecutor, as_completed


def load_local_env():
    """Charge un fichier .env local si présent (utile dans Termux).

    Les variables déjà exportées dans le shell restent prioritaires.
    Format supporté: NOM=valeur, avec guillemets optionnels.
    """
    candidates = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
    ]

    for env_path in candidates:
        if not os.path.exists(env_path):
            continue

        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = value
        except Exception as e:
            print(f"Attention: impossible de lire {env_path}: {e}", file=sys.stderr)


load_local_env()


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
SLEEP_SECONDS = float(os.environ.get("WORKER_SLEEP_SECONDS", "2"))
PREFETCH_MAX_MATCHES_PER_PAGE = int(os.environ.get("PREFETCH_MAX_MATCHES_PER_PAGE", "17"))

PAGES_TO_LOAD = int(os.environ.get("FOOTSCAN_PAGES_TO_LOAD", "40"))
PAGE_LOAD_STEPS = [10, 15, 20, 30, 40]
INITIAL_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_INITIAL_MATCHES_PER_TEAM", "15"))
SECOND_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_SECOND_MATCHES_PER_TEAM", "17"))
MAX_MATCHES_PER_TEAM = int(os.environ.get("FOOTSCAN_MAX_MATCHES_PER_TEAM", "100"))
INCIDENT_BATCH_SIZE = int(os.environ.get("FOOTSCAN_INCIDENT_BATCH_SIZE", "2"))
INCIDENT_MAX_WORKERS = int(os.environ.get("FOOTSCAN_INCIDENT_MAX_WORKERS", "6"))
SOFA_FETCH_RETRIES = int(os.environ.get("SOFA_FETCH_RETRIES", "2"))
SOFA_RETRY_SLEEP_SECONDS = float(os.environ.get("SOFA_RETRY_SLEEP_SECONDS", "0.4"))
SOFA_FETCH_TIMEOUT_SECONDS = int(os.environ.get("SOFA_FETCH_TIMEOUT_SECONDS", "12"))
SOFA_DEBUG_NETWORK = os.environ.get("SOFA_DEBUG_NETWORK", "0").strip().lower() in ("1", "true", "oui", "yes")
SOFA_INCIDENT_TIMEOUT_SECONDS = int(os.environ.get("SOFA_INCIDENT_TIMEOUT_SECONDS", "8"))
SOFA_INCIDENT_RETRIES = int(os.environ.get("SOFA_INCIDENT_RETRIES", "1"))
PREFETCH_ENABLED = os.environ.get("FOOTSCAN_PREFETCH_ENABLED", "0") == "1"
DEFAULT_RANK_EVENT_STEP = 1.0
CURRENT_RANK_EVENT_STEP = DEFAULT_RANK_EVENT_STEP
CURRENT_RANK_ADVANCEMENT_MODE = "fixed"


def configure_rank_advancement(step=None, mode=None):
    """Configure l'avancement des rangs pour le job en cours.

    mode="fixed" : chaque événement avance de CURRENT_RANK_EVENT_STEP.
    mode="performance" : chaque événement avance selon sa valeur absolue de performance.
    """
    global CURRENT_RANK_EVENT_STEP, CURRENT_RANK_ADVANCEMENT_MODE

    try:
        parsed_step = float(step) if step is not None else DEFAULT_RANK_EVENT_STEP
    except Exception:
        parsed_step = DEFAULT_RANK_EVENT_STEP

    if not math.isfinite(parsed_step) or parsed_step <= 0:
        parsed_step = DEFAULT_RANK_EVENT_STEP

    CURRENT_RANK_EVENT_STEP = parsed_step
    CURRENT_RANK_ADVANCEMENT_MODE = "performance" if mode == "performance" else "fixed"


def rank_advancement_label():
    if CURRENT_RANK_ADVANCEMENT_MODE == "performance":
        return "valeur de performance"
    return f"{CURRENT_RANK_EVENT_STEP:.4f} par événement"

GOAL_WITH_PASSER_VALUE = 1.0
GOAL_WITHOUT_PASSER_VALUE = 2 / 3
GOAL_ERROR_VALUE = 1 / 3

POSITIVE_VALUES = {
    "goalWithAssist": GOAL_WITH_PASSER_VALUE,
    "goal": GOAL_WITHOUT_PASSER_VALUE,
}

NEGATIVE_VALUES_FOR_TEAM = {
    "ownGoal": -GOAL_ERROR_VALUE,
}

CARD_VALUES_FOR_TEAM = {
    "yellow": -0.25,
    "secondYellow": -0.5,
    "red": -1,
    "redFromSecondYellow": -1.5,
}

LABELS = {
    "goal": "But Sans Passeur",
    "goalWithAssist": "But Avec Passeur",
    "goalNoAssistError": "CSC / Erreur",
    "assist": "Passe décisive",
    "yellow": "Jaune",
    "secondYellow": "Deuxième jaune",
    "red": "Rouge direct",
    "redFromSecondYellow": "Rouge via 2e jaune",
    "ownGoal": "CSC / Erreur",
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

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Upstash HTTP {e.code}: {raw[:300]}")

    data = json.loads(raw)

    if data.get("error"):
        raise RuntimeError(f"Upstash error: {data['error']}")

    return data.get("result")


def is_upstash_quota_error(error):
    text = str(error).lower()
    return "max requests limit exceeded" in text or "max daily request" in text or "max request" in text


def parse_brpop_result(result):
    """Retourne (queue_key, value) pour BRPOP, ou (None, None).

    Upstash renvoie normalement [key, value]. On reste tolérant
    si le format varie légèrement.
    """
    if not result:
        return None, None
    if isinstance(result, (list, tuple)) and len(result) >= 2:
        return str(result[0]), result[1]
    return None, result


def read_url(url, headers, impersonate=False, timeout=None):
    # Si curl_cffi est dispo, on imite l'empreinte TLS de Chrome :
    # c'est ce qui contourne le 403 "challenge" (anti-bot) de SofaScore.
    if impersonate and HAS_CURL_CFFI:
        try:
            resp = cffi_requests.get(url, headers=headers, timeout=timeout or SOFA_FETCH_TIMEOUT_SECONDS, impersonate="chrome")
            return resp.status_code, resp.text
        except Exception as e:
            return 0, str(e)

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout or SOFA_FETCH_TIMEOUT_SECONDS) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            return status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        # Erreurs réseau Termux / mobile : on remonte une erreur spéciale.
        # sofa_fetch fera les retry avant d'abandonner.
        return 0, str(e)


def read_url_syscurl(url, headers, timeout=None):
    """Transport de secours via le binaire curl de Termux (pkg install curl).

    Son empreinte TLS differe de celle de Python : il passe parfois
    la ou urllib est bloque."""
    if not shutil.which("curl"):
        return 0, "curl absent (pkg install curl)"

    t = int(timeout or SOFA_FETCH_TIMEOUT_SECONDS)
    cmd = ["curl", "-sS", "-L", "--http1.1", "--compressed", "--connect-timeout", str(max(3, min(10, t))), "--max-time", str(max(5, t)),
           "-w", "\n%{http_code}", url]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=max(8, int(timeout or SOFA_FETCH_TIMEOUT_SECONDS) + 5))
        raw = out.stdout
        if "\n" not in raw:
            return 0, (out.stderr or "reponse curl vide").strip()
        body, _, code = raw.rpartition("\n")
        return int(code or 0), body
    except Exception as e:
        return 0, str(e)


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
        return None, f"{source}: erreur Web sur {path}: {data['error']}"

    return body, None


def sofa_fetch(path, incident_mode=False):
    clean_path = path.lstrip("/")
    incident_mode = incident_mode or bool(re.match(r"^event/\d+/incidents$", clean_path))

    app_url = f"https://api.sofascore.app/api/v1/{clean_path}"
    www_url = f"https://www.sofascore.com/api/v1/{clean_path}"
    api_url = f"https://api.sofascore.com/api/v1/{clean_path}"

    # L'app Android n'envoie NI Referer NI Origin : les envoyer sur l'hôte
    # .app paraît suspect. On imite donc l'app sur .app, le navigateur sur .com.
    app_headers = {
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
    }

    browser_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Mobile Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        "Referer": "https://www.sofascore.com/",
        "Origin": "https://www.sofascore.com",
        "Cache-Control": "no-cache",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "X-Requested-With": "XMLHttpRequest",
    }

    # (url, headers, transport) — du plus prometteur au plus désespéré.
    # Pour les incidents, on évite les longues boucles urllib: si SofaScore
    # renvoie un challenge 403, le match sera ignoré proprement par le scan.
    if incident_mode:
        targets = [
            (www_url, browser_headers, "cffi"),
            (api_url, browser_headers, "cffi"),
            (app_url, app_headers, "syscurl"),
            (www_url, browser_headers, "syscurl"),
            (api_url, browser_headers, "syscurl"),
            (app_url, app_headers, "urllib"),
        ]
        retries = max(1, SOFA_INCIDENT_RETRIES)
        timeout = SOFA_INCIDENT_TIMEOUT_SECONDS
    else:
        targets = [
            # curl_cffi d'abord quand il est disponible : moins de faux messages
            # "réponse vide" au démarrage Termux, et meilleure empreinte navigateur.
            (www_url, browser_headers, "cffi"),
            (api_url, browser_headers, "cffi"),
            (app_url, app_headers, "urllib"),
            (www_url, browser_headers, "syscurl"),
            (api_url, browser_headers, "syscurl"),
            (app_url, app_headers, "syscurl"),
            (www_url, browser_headers, "urllib"),
            (api_url, browser_headers, "urllib"),
        ]
        retries = SOFA_FETCH_RETRIES
        timeout = SOFA_FETCH_TIMEOUT_SECONDS

    last_error = None
    challenge_seen = False

    for attempt in range(1, retries + 1):
        for url, headers, transport in targets:
            if transport == "cffi":
                if not HAS_CURL_CFFI:
                    continue
                status, body = read_url(url, headers, impersonate=True, timeout=timeout)
            elif transport == "syscurl":
                status, body = read_url_syscurl(url, headers, timeout=timeout)
            else:
                status, body = read_url(url, headers, timeout=timeout)

            valid_body, error = validate_json(status, body, clean_path, f"{url} [{transport}]")

            if valid_body is not None:
                return valid_body

            last_error = error

            if status == 403 and "challenge" in (body or ""):
                challenge_seen = True

            # 404 = page absente : c'est normal quand l'historique SofaScore s'arrête.
            # On remonte l'information au scan, mais sans l'afficher comme une erreur Termux.
            if status == 404:
                if SOFA_DEBUG_NETWORK:
                    print(f"Fin historique / ressource absente: {error}", file=sys.stderr)
                raise RuntimeError(error)

            if SOFA_DEBUG_NETWORK:
                print(f"Échec tentative {attempt}/{retries}: {error}", file=sys.stderr)

        if attempt < retries:
            time.sleep(SOFA_RETRY_SLEEP_SECONDS * attempt)

    if challenge_seen and not HAS_CURL_CFFI:
        print(
            "ASTUCE : SofaScore bloque l'empreinte TLS de Python (403 challenge).\n"
            "Deux solutions, de la plus simple à la plus robuste :\n"
            "  1. Dans Termux : pkg install curl   (active le transport curl)\n"
            "  2. Ubuntu via proot-distro pour utiliser curl_cffi :\n"
            "       pkg install proot-distro\n"
            "       proot-distro install ubuntu\n"
            "       proot-distro login ubuntu\n"
            "       apt update && apt install -y python3-pip\n"
            "       pip3 install curl_cffi\n"
            "       puis relancer le worker depuis Ubuntu.",
            file=sys.stderr,
        )

    raise RuntimeError(
        (last_error or f"Impossible de récupérer {clean_path}")
        + f" | curl_cffi={'oui' if HAS_CURL_CFFI else 'non'}"
        + f" curl_systeme={'oui' if shutil.which('curl') else 'non'}"
    )

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


def get_incidents_json(path):
    """Récupère les incidents sans bloquer tout le scan si SofaScore challenge.

    SofaScore renvoie parfois 403 {reason: challenge} sur /incidents. Dans ce
    cas on retourne une liste vide pour le match concerné: le scan continue,
    le match est marqué à 0 événement au lieu de faire planter ou attendre.
    """
    clean_path = path.lstrip("/")
    cached = get_cached_body(clean_path)

    if cached:
        return json.loads(cached)

    try:
        body = sofa_fetch(clean_path, incident_mode=True)
        set_cache(clean_path, body)
        return json.loads(body)
    except Exception as e:
        msg = str(e)
        if "challenge" in msg or "HTTP 403" in msg:
            if SOFA_DEBUG_NETWORK:
                print(f"Incidents non récupérés (SofaScore challenge): {clean_path}", file=sys.stderr)
            return {
                "incidents": [],
                "_footscanIssue": {
                    "type": "blocked",
                    "reason": "SofaScore challenge",
                    "path": clean_path,
                    "message": "SofaScore a bloqué la récupération des événements de ce match.",
                },
            }
        raise


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
    if not PREFETCH_ENABLED:
        return

    clean_path = path.lstrip("/")

    if not re.match(r"^team/\d+/events/last/\d+$", clean_path):
        return

    events = extract_events_from_body(body)
    finished = []

    for match in events:
        if not isinstance(match, dict):
            continue

        if administrative_match_reason(match):
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
        print(f"Préchargement événements ajouté: {count} match(s) depuis {clean_path}")


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


def normalize_status_text(value):
    text = str(value or "").strip().lower()
    replacements = {
        "é": "e", "è": "e", "ê": "e", "ë": "e",
        "à": "a", "â": "a", "ä": "a",
        "î": "i", "ï": "i",
        "ô": "o", "ö": "o",
        "ù": "u", "û": "u", "ü": "u",
        "ç": "c",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text


ADMIN_MATCH_KEYWORDS = (
    "forfeit", "forfait",
    "walkover", "walk over",
    "awarded", "award",
    "abandoned", "abandonne",
    "cancelled", "canceled", "annule",
    "postponed", "reporte",
    "suspended", "suspendu",
    "interrupted", "interrompu",
    "retired",
    "defaulted", "default loss", "default win",
    "technical defeat", "technical loss", "technical win",
)


def administrative_match_reason(match):
    """Retourne une raison si le match doit être exclu du calcul sportif.

    Règle FOOTSCAN : tout match décidé administrativement ou non terminé
    normalement est ignoré entièrement. Cela évite de compter des buts d'un
    match abandonné/forfait/attribué dont le résultat officiel ne reflète plus
    une performance sportive comparable.
    """
    if not isinstance(match, dict):
        return "Format match invalide"

    status = match.get("status") or {}
    status_type = normalize_status_text(status.get("type"))

    if status_type and status_type != "finished":
        return f"Statut non terminé normalement: {status.get('type')}"

    values = []

    def add(value):
        if value is None:
            return
        if isinstance(value, (str, int, float, bool)):
            values.append(str(value))

    # Champs SofaScore connus ou fréquents pour les statuts administratifs.
    for key in ("type", "description", "reason", "text", "name", "short", "detail"):
        add(status.get(key))

    for key in (
        "statusDescription", "statusText", "statusReason", "reason",
        "note", "notes", "description", "resultType", "matchStatus",
        "defaultScore", "defaultWinner", "forfeit", "walkover",
        "awarded", "abandoned", "cancelled", "canceled", "postponed",
        "suspended", "interrupted", "retired",
    ):
        add(match.get(key))

    haystack = " | ".join(normalize_status_text(v) for v in values if str(v).strip())

    if not haystack:
        return None

    for keyword in ADMIN_MATCH_KEYWORDS:
        if keyword in haystack:
            return f"Statut administratif détecté: {keyword}"

    # Cas de booléens explicites, si l'API les fournit.
    for key in ("forfeit", "walkover", "awarded", "abandoned", "cancelled", "canceled", "postponed", "suspended", "interrupted", "retired"):
        if match.get(key) is True:
            return f"Statut administratif détecté: {key}"

    return None


def make_administrative_match_issue(match, reason):
    return {
        "id": match.get("id"),
        "label": make_match_label(match),
        "competition": get_competition_name(match),
        "startTimestamp": match.get("startTimestamp") or 0,
        "type": "administrative",
        "reason": reason or "Match administratif / forfait",
        "message": "Match ignoré: forfait, abandon, report, annulation ou décision administrative.",
    }


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

    # Pour un CSC, Web peut comptabiliser le but pour l'équipe bénéficiaire.
    # Dans notre méthode, on veut toujours attribuer l'événement au joueur/club
    # qui marque contre son camp. On privilégie donc l'équipe du joueur.
    player_team_id = (
        ((incident.get("playerTeam") or {}).get("id")) or
        ((player.get("team") or {}).get("id"))
    )

    if player_team_id:
        return player_team_id == analyzed_team_id

    # Repli: si Web place isHome du côté bénéficiaire du but,
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


def incident_assist_name(incident):
    """Retourne un nom de passeur si SofaScore expose une passe décisive."""
    if not isinstance(incident, dict):
        return None

    for key in ("assist1", "assist2", "assist", "assistPlayer"):
        assist = incident.get(key)

        if isinstance(assist, dict):
            name = assist.get("name") or assist.get("shortName") or assist.get("slug")
            if name:
                return str(name)

        if isinstance(assist, str) and assist.strip():
            return assist.strip()

    return None


def match_contains_goal_assist(incidents):
    """Indique si le match contient au moins une passe décisive récupérée."""
    for incident in incidents or []:
        if not isinstance(incident, dict):
            continue

        if incident.get("incidentType") != "goal":
            continue

        if is_own_goal_incident(incident):
            continue

        minute = incident.get("time")
        if minute is None or minute < 1 or minute > 90:
            continue

        if incident_assist_name(incident):
            return True

    return False


def parse_incidents(incidents, match, analyzed_team_id):
    """Récupère uniquement les buts.

    Les cartons et les passes décisives seules ne sont pas parcourus.
    Les seuls événements conservés sont :
    - But Avec Passeur = performance 1 ;
    - But Sans Passeur = performance 2/3, attribuée uniquement au camp qui marque ;
    - CSC / Erreur = performance -1/3 pour l'équipe qui marque contre son camp.

    Important : un But Sans Passeur ne crée plus d'événement d'erreur
    artificiel pour l'équipe qui encaisse.
    """
    events = []
    match_label = make_match_label(match)
    match_id = match.get("id")
    match_has_assists = match_contains_goal_assist(incidents)

    def common_event_fields(minute, added, minute_label, side, match_has_assists):
        return {
            "minute": minute,
            "added": added,
            "minuteLabel": minute_label,
            "match": match_label,
            "matchId": match_id,
            "matchHasAssists": match_has_assists,
            "assistDataStatus": "assist-found" if match_has_assists else "no-assist-found",
            "side": side,
        }

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
                **common_event_fields(minute, added, minute_label, side, match_has_assists),
                "detail": f"{camp_label} · CSC / Erreur · {scorer}",
                "icon": "🥅",
            })
            continue

        assister = incident_assist_name(inc)

        if assister:
            events.append({
                "type": "goalWithAssist",
                "value": signed_attack_value("goalWithAssist", is_for_team),
                **common_event_fields(minute, added, minute_label, side, match_has_assists),
                "detail": f"{camp_label} · But Avec Passeur · {scorer} — passe : {assister}",
                "icon": "⚽",
            })
        else:
            # Un But Sans Passeur compte désormais uniquement comme un
            # événement du camp qui marque. Il ne crée plus de 1/3 d'erreur
            # artificielle pour le camp qui encaisse.
            events.append({
                "type": "goal",
                "value": signed_attack_value("goal", is_for_team),
                **common_event_fields(minute, added, minute_label, side, match_has_assists),
                "detail": f"{camp_label} · But Sans Passeur · {scorer}",
                "icon": "⚽",
                "subOrder": 0,
            })

    def sort_key(ev):
        time_value = ev.get("minute", 0) + (ev.get("added", 0) or 0)
        order = {
            "goalWithAssist": 0,
            "goal": 0,
            "ownGoal": 1,
            "goalNoAssistError": 1,
        }.get(ev.get("type"), 9)
        return (-time_value, ev.get("subOrder", order), order)

    events.sort(key=sort_key)
    return events

def event_rank_quantity(event):
    """Quantité qui fait avancer le rang.

    Mode fixe : chaque événement avance de la valeur choisie dans le curseur
    Avancement / Progression.

    Mode performance : chaque événement avance selon sa performance absolue :
    - But Avec Passeur : 1
    - But Sans Passeur : 2/3
    - CSC / Erreur : 1/3

    Les valeurs négatives avancent aussi en positif, car le rang représente
    une distance parcourue dans la liste d'événements.
    """
    if not isinstance(event, dict):
        return 0.0

    try:
        value = float(event.get("value", 0))
    except Exception:
        return 0.0

    if not math.isfinite(value):
        return 0.0

    try:
        weight = float(event.get("weight", 1))
    except Exception:
        weight = 1.0

    if not math.isfinite(weight) or weight <= 0:
        weight = 1.0

    # La pondération des adversaires passés agit uniquement sur la
    # progression des rangs. Elle ne modifie jamais la performance brute
    # de l'événement, qui reste stockée dans event["value"].
    if CURRENT_RANK_ADVANCEMENT_MODE == "performance":
        return abs(value) * weight

    return CURRENT_RANK_EVENT_STEP * weight


def total_rank_quantity(events):
    return sum(event_rank_quantity(event) for event in (events or []))


def direct_team_rank_quantity(events):
    """Progression portée uniquement par les événements directs de l'équipe.

    En mode simultané, l'ancien arrêt se faisait sur le total brut
    équipe + adversaire. Cela pouvait arrêter le scan alors que le flux direct
    d'une équipe n'avait pas encore assez de progression pour atteindre le rang
    haut. Le résultat affichait alors un "—" malgré beaucoup d'événements
    bruts récupérés.
    """
    return sum(
        event_rank_quantity(event)
        for event in (events or [])
        if isinstance(event, dict) and event.get("side") == "team"
    )


def scan_completion_quantity(events, completion_mode="total"):
    if completion_mode == "team_direct":
        return direct_team_rank_quantity(events)
    return total_rank_quantity(events)


def trim_events_to_rank_need(events, max_needed):
    """Garde seulement les événements réellement nécessaires pour atteindre le rang demandé.

    En mode simultané, le worker récupère volontairement une marge plus large pour
    pouvoir réattribuer les événements adverses. Cette marge ne doit pas remonter
    dans l'interface: le site doit afficher uniquement ce qui a été utilisé jusqu'au
    dernier événement nécessaire.
    """
    try:
        needed = float(max_needed)
    except Exception:
        needed = 0

    clean_events = [event for event in (events or []) if event_rank_quantity(event) > 0]

    if needed <= 0 or not clean_events:
        return clean_events

    used = []
    progress = 0.0

    for event in clean_events:
        used.append(event)
        progress += event_rank_quantity(event)

        if progress >= needed:
            break

    return used


def build_matches_used_from_events(events):
    """Reconstruit la liste des matchs réellement utilisés depuis les événements affichés."""
    order = []
    by_id = {}

    for event in events or []:
        match_id = event.get("matchId")
        if match_id is None:
            # Repli très rare: garder une clé stable si l'ID manque.
            match_id = event.get("match") or f"event-{len(order) + 1}"

        if match_id not in by_id:
            order.append(match_id)
            by_id[match_id] = {
                "id": match_id,
                "label": event.get("match") or "Match",
                "count": 0,
                "startTimestamp": event.get("startTimestamp") or event.get("sourceStartTimestamp") or 0,
                "competition": event.get("competition") or event.get("sourceCompetition") or "Toutes compétitions",
                "eventDataStatus": event.get("eventDataStatus") or "ok",
                "simultaneousUsedOnly": True,
            }

        by_id[match_id]["count"] += 1

    return [by_id[match_id] for match_id in order]


def trim_scan_display_to_used(scan, max_needed):
    """Retourne une copie de scan limitée à la partie réellement exploitée.

    Important: ne modifie pas les calculs de récupération. On nettoie seulement les
    listes renvoyées au front après le reclassement simultané, pour que
    "matchs utilisés" et "événements trouvés" ne comptent pas la marge.
    """
    result = dict(scan or {})
    used_events = trim_events_to_rank_need(result.get("events") or [], max_needed)
    result["events"] = used_events
    result["matchesUsed"] = build_matches_used_from_events(used_events)
    result["displayTrimmedToRankNeed"] = True
    result["displayProgressionUsed"] = round(total_rank_quantity(used_events), 4)
    result["displayEventCount"] = len(used_events)
    result["displayMatchCount"] = len(result["matchesUsed"])
    return result


def opponent_past_source_match_key(event, fallback_index=0):
    """Clé stable du match source pour un événement ADV pondéré."""
    if not isinstance(event, dict):
        return f"adv-{fallback_index}"

    match_id = event.get("sourceMatchId") or event.get("matchId")
    if match_id is None:
        match_id = event.get("match") or f"adv-{fallback_index}"

    return str(match_id)


def set_opponent_past_progression_divisor(events, divisor):
    """Applique un diviseur uniquement à la progression des événements ADV."""
    try:
        divisor = int(divisor)
    except Exception:
        divisor = 1

    divisor = max(1, divisor)
    weight = round(1 / divisor, 6)

    for event in events or []:
        if not isinstance(event, dict) or not event.get("opponentPastWeighted"):
            continue
        event["opponentPastDivisor"] = divisor
        event["weight"] = weight


def trim_events_to_rank_need_realtime_opponent_past(events, max_needed):
    """Trim avec division ADV recalculée en temps réel.

    Dès qu'un nouveau match source ADV entre dans la tranche utilisée, le
    diviseur augmente et s'applique immédiatement à tout le passé déjà gardé,
    à l'événement courant et aux suivants. La performance brute n'est jamais
    modifiée: seul event["weight"] change pour la progression des rangs.
    """
    try:
        needed = float(max_needed)
    except Exception:
        needed = 0

    used = []
    adv_match_ids = set()
    divisor = 1

    for source_index, event in enumerate(events or [], start=1):
        if not isinstance(event, dict):
            continue

        copied = dict(event)

        if copied.get("opponentPastWeighted"):
            adv_match_ids.add(opponent_past_source_match_key(copied, source_index))
            divisor = max(1, len(adv_match_ids))

        used.append(copied)

        # Impact passé + présent + futur : dès que le diviseur change, on
        # réécrit la progression de tous les ADV déjà présents dans la tranche.
        set_opponent_past_progression_divisor(used, divisor)

        if needed > 0 and total_rank_quantity(used) >= needed:
            break

    set_opponent_past_progression_divisor(used, divisor)
    return used, divisor


def finalize_simultaneous_scan_to_used(scan, max_needed):
    """Finalise un flux simultané avec diviseur ADV dynamique.

    Le diviseur n'est pas un compteur global final. Il avance en temps réel
    dans le calcul cible : pour les rangs de A, seuls les matchs source B dont
    les événements ADV entrent réellement dans la tranche de A augmentent le
    diviseur; le même principe s'applique séparément pour B.
    """
    result = dict(scan or {})
    events = [dict(event) for event in (result.get("events") or [])]

    used_events, divisor = trim_events_to_rank_need_realtime_opponent_past(events, max_needed)

    result["events"] = used_events
    result["matchesUsed"] = build_matches_used_from_events(used_events)
    result["displayTrimmedToRankNeed"] = True
    result["displayProgressionUsed"] = round(total_rank_quantity(used_events), 4)
    result["displayEventCount"] = len(used_events)
    result["displayMatchCount"] = len(result["matchesUsed"])
    result["simultaneousTargetSpecificAdvDivisor"] = divisor
    result["realtimeOpponentPastDivisor"] = divisor
    return result


def rebuild_simultaneous_combined_events(home_scan, away_scan):
    """Reconstruit la liste commune à partir des deux flux déjà finalisés."""
    combined = []
    for event in (home_scan.get("events") or []) + (away_scan.get("events") or []):
        if isinstance(event, dict):
            combined.append(dict(event))

    combined.sort(key=lambda event: (event.get("simultaneousIndex") or 0, event.get("simultaneousTarget") or ""))
    return combined


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

    En mode fixe, on garde l'interpolation exacte entre les événements :
    le rang demandé est converti en position exacte dans la liste.

    En mode performance, l'avancement varie selon l'événement. On cherche
    donc l'événement dont la zone de cumul contient exactement le rang demandé.
    """
    mode = CURRENT_RANK_ADVANCEMENT_MODE

    if rank is None or rank <= 0:
        return {"value": None, "sources": [], "rankMode": "quantity_exact", "eventStepMode": mode}

    try:
        target_rank = float(rank)
    except Exception:
        return {"value": None, "sources": [], "rankMode": "quantity_exact", "eventStepMode": mode}

    if target_rank <= 0:
        return {"value": None, "sources": [], "rankMode": "quantity_exact", "eventStepMode": mode}

    clean_events = [event for event in (events or []) if event_rank_quantity(event) > 0]

    if not clean_events:
        return {
            "value": None,
            "sources": [],
            "rankMode": "quantity_exact",
            "eventStepMode": mode,
            "eventStep": CURRENT_RANK_EVENT_STEP,
            "targetRank": target_rank,
            "totalQuantity": 0,
        }

    total_quantity = sum(event_rank_quantity(event) for event in clean_events)

    if target_rank > total_quantity + 1e-9:
        return {
            "value": None,
            "sources": [],
            "rankMode": "quantity_exact",
            "eventStepMode": mode,
            "eventStep": CURRENT_RANK_EVENT_STEP,
            "targetRank": target_rank,
            "totalQuantity": round(total_quantity, 6),
        }

    if mode == "performance":
        cumulative = 0.0

        for event_index, event in enumerate(clean_events):
            quantity = event_rank_quantity(event)
            cumulative_start = cumulative
            cumulative_end = cumulative + quantity

            if cumulative_end >= target_rank - 1e-9:
                source = annotate_rank_source(event, event_index, cumulative_start, cumulative_end, target_rank)
                source["weight"] = 1
                source["rankMode"] = "quantity_performance"

                return {
                    "value": float(source.get("value", 0)),
                    "sources": [source],
                    "rankMode": "quantity_performance",
                    "eventStepMode": mode,
                    "eventStep": CURRENT_RANK_EVENT_STEP,
                    "targetRank": target_rank,
                    "totalQuantity": round(total_quantity, 6),
                }

            cumulative = cumulative_end

        return {
            "value": None,
            "sources": [],
            "rankMode": "quantity_performance",
            "eventStepMode": mode,
            "eventStep": CURRENT_RANK_EVENT_STEP,
            "targetRank": target_rank,
            "totalQuantity": round(total_quantity, 6),
        }

    step = CURRENT_RANK_EVENT_STEP
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
                "eventStepMode": mode,
                "eventStep": step,
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
            "eventStepMode": mode,
            "eventStep": step,
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
            "eventStepMode": mode,
            "eventStep": step,
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
            "eventStepMode": mode,
            "eventStep": step,
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
        "eventStepMode": mode,
        "eventStep": step,
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

    Nouvelle logique: l’avancement vient du curseur ou de la valeur de performance selon l’option choisie.

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
        "eventStepMode": CURRENT_RANK_ADVANCEMENT_MODE,
        "eventStep": CURRENT_RANK_EVENT_STEP,
        "eventStepLabel": rank_advancement_label(),
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
        "eventStepMode": CURRENT_RANK_ADVANCEMENT_MODE,
        "eventStep": CURRENT_RANK_EVENT_STEP,
        "eventStepLabel": rank_advancement_label(),
        "groupMode": group_mode,
    }


def zone_events_between_ranks(events, rank1, rank2=None):
    """Retourne les événements situés entre deux rangs, rangs finaux inclus.

    Nouvelle logique: la zone est basée sur le cumul d’avancement choisi, pas sur un rang 1 événement = 1.
    """
    selected_events, start_rank_value, end_rank_value, _selected_quantity = events_between_rank_quantities(events, rank1, rank2)
    return selected_events, start_rank_value, end_rank_value


def simultaneous_overall_zone_stats(combined_events, rank1, rank2=None):
    """Zone collective simultanée générale.

    Pour la moyenne globale uniquement, on parcourt la liste collective complète :
    équipe A + équipe B + adversaire passé de A + adversaire passé de B.

    Les rangs utilisés restent ceux indiqués : pas de multiplication automatique.

    Chaque événement avance selon le curseur ou selon sa valeur de performance.
    """
    try:
        used_rank1 = float(rank1)
        used_rank2 = float(rank2) if rank2 is not None else used_rank1
    except Exception:
        used_rank1 = rank1
        used_rank2 = rank2

    result = zone_stats_between_ranks(combined_events or [], used_rank1, used_rank2, group_mode="global")
    result["globalMethod"] = "combined_all_events_rank_advancement"
    result["rankMultiplier"] = 1
    result["eventStep"] = CURRENT_RANK_EVENT_STEP
    result["eventStepMode"] = CURRENT_RANK_ADVANCEMENT_MODE
    result["eventStepLabel"] = rank_advancement_label()
    result["originalRank1"] = rank1
    result["originalRank2"] = rank2
    result["usedRank1"] = used_rank1
    result["usedRank2"] = used_rank2
    result["combinedEventCount"] = len(combined_events or [])
    return result

def direct_team_events_only(events):
    """Garde uniquement les événements propres à l'équipe analysée."""
    return [event for event in (events or []) if isinstance(event, dict) and event.get("side") == "team"]


def opponent_past_events_for_separate(events):
    """
    Calcul séparé v130 : ajoute les événements directs des adversaires passés.

    Ils sont remis dans le sens de l'adversaire qui les a vraiment produits,
    puis pondérés dynamiquement par le nombre de matchs utilisés. Les
    événements directs de l'équipe analysée ne sont jamais pondérés.
    """
    converted = []

    for event in events or []:
        if not isinstance(event, dict) or event.get("side") != "opponent":
            continue

        copied = dict(event)

        try:
            raw_value = -float(copied.get("value", 0))
        except Exception:
            raw_value = 0.0

        copied["side"] = "opponent"
        copied["displaySide"] = "Adversaire passé"
        copied["originLabel"] = "adversaire passé"
        copied["linkedFromOpponentPast"] = True
        copied["opponentPastWeighted"] = True
        copied["opponentPastRawValue"] = round(raw_value, 6)
        copied["value"] = round(raw_value, 6)
        copied["weight"] = 1
        copied["opponentPastDivisor"] = 1

        detail = str(copied.get("detail") or "")
        for prefix in ("Équipe analysée · ", "Adversaire · "):
            if detail.startswith(prefix):
                detail = detail[len(prefix):]
                break
        copied["detail"] = f"Adversaire passé · {detail}" if detail else "Adversaire passé"

        converted.append(copied)

    return converted


def separate_mode_events(events):
    """Équipe analysée directe + adversaires passés pondérés."""
    return direct_team_events_only(events) + opponent_past_events_for_separate(events)


def renormalize_opponent_past_events(events, matches_used_count):
    """
    Applique la division dynamique demandée :
    adversaires passés / nombre de matchs utilisés.

    Le nombre brut d'événements reste inchangé. La performance brute
    de l'événement reste inchangée aussi. Seule la progression de rang
    des événements adversaires passés est pondérée.
    """
    try:
        divisor = int(matches_used_count)
    except Exception:
        divisor = 1

    divisor = max(1, divisor)
    weight = 1 / divisor

    for event in events or []:
        if not isinstance(event, dict) or not event.get("opponentPastWeighted"):
            continue

        try:
            raw_value = float(event.get("opponentPastRawValue", event.get("value", 0)))
        except Exception:
            raw_value = 0.0

        event["opponentPastDivisor"] = divisor
        event["weight"] = round(weight, 6)
        # Important : la division ne touche pas la performance.
        # Elle sert uniquement à faire avancer les rangs moins vite.
        event["value"] = round(raw_value, 6)


def scan_team(job_id, analyzed_team_id, skip, max_needed, team_name, base_progress, progress_span, direct_team_only=False, completion_mode="total"):
    update_scan_job(
        job_id,
        status="running",
        message=f"{team_name} · Récupération Des Pages Web…",
        progress=base_progress,
    )

    pages = []
    stopped_history = False
    administrative_matches_ignored = {}

    def build_finished_matches():
        by_id = {}

        for match in pages:
            if not isinstance(match, dict):
                continue

            match_id = match.get("id")

            if not match_id:
                continue

            home_id = (match.get("homeTeam") or {}).get("id")
            away_id = (match.get("awayTeam") or {}).get("id")

            if home_id != analyzed_team_id and away_id != analyzed_team_id:
                continue

            admin_reason = administrative_match_reason(match)
            if admin_reason:
                administrative_matches_ignored[match_id] = make_administrative_match_issue(match, admin_reason)
                continue

            by_id[match_id] = match

        return by_id

    page_targets = [step for step in PAGE_LOAD_STEPS if step <= PAGES_TO_LOAD]
    if PAGES_TO_LOAD not in page_targets:
        page_targets.append(PAGES_TO_LOAD)

    next_page = 0
    pages_loaded_count = 0
    pages_attempted_count = 0
    by_id = {}

    for target_pages in page_targets:
        if stopped_history:
            break

        for page in range(next_page, target_pages):
            update_scan_job(
                job_id,
                status="running",
                message=f"{team_name} · Page {page + 1}/{target_pages}",
                progress=base_progress + int(progress_span * 0.10 * ((page + 1) / max(1, target_pages))),
            )

            page_path = f"team/{analyzed_team_id}/events/last/{page}"
            pages_attempted_count = max(pages_attempted_count, page + 1)

            try:
                data = get_json(page_path)
            except Exception as e:
                error_text = str(e)

                # Web renvoie parfois 404 quand une équipe n'a plus de page historique.
                # Ce n'est pas une vraie erreur de scan : on s'arrête simplement aux pages déjà récupérées.
                if "HTTP 404" in error_text or "Not Found" in error_text:
                    update_scan_job(
                        job_id,
                        status="running",
                        message=(
                            f"{team_name} · Fin De L'Historique Web À La Page {page + 1}.\n"
                            f"Pages récupérées : {page}/{target_pages}"
                        ),
                        progress=base_progress + int(progress_span * 0.10),
                    )
                    stopped_history = True
                    break

                # Erreur réseau sur une page historique : si on a déjà des pages, on continue
                # avec ce qu'on a au lieu de faire planter tout le scan. Si la page 0 plante,
                # on remonte l'erreur car on n'a aucune base pour analyser l'équipe.
                if pages:
                    update_scan_job(
                        job_id,
                        status="running",
                        message=(
                            f"{team_name} · Page {page + 1} Ignorée Après Erreur Réseau.\n"
                            f"Pages déjà récupérées : {page}/{target_pages}"
                        ),
                        progress=base_progress + int(progress_span * 0.10),
                    )
                    stopped_history = True
                    break

                raise

            page_events = data.get("events") if isinstance(data, dict) else data

            if isinstance(page_events, list) and page_events:
                pages.extend(page_events)
                pages_loaded_count = max(pages_loaded_count, page + 1)
            else:
                update_scan_job(
                    job_id,
                    status="running",
                    message=f"{team_name} · Page {page + 1} Vide, Arrêt De L'Historique.",
                    progress=base_progress + int(progress_span * 0.10),
                )
                stopped_history = True
                break

        next_page = max(next_page, target_pages)
        by_id = build_finished_matches()

        # On démarre avec 10 pages. Si elles ne suffisent pas pour alimenter le scan
        # progressif après les matchs ignorés/pondérés, on étend automatiquement
        # à 15, 20, 30 puis 40 pages.
        if len(by_id) >= skip + MAX_MATCHES_PER_TEAM:
            break

        if target_pages < PAGES_TO_LOAD and not stopped_history:
            next_target = next((step for step in page_targets if step > target_pages), PAGES_TO_LOAD)
            update_scan_job(
                job_id,
                status="running",
                message=(
                    f"{team_name} · 10 Pages Insuffisantes, Extension Jusqu’à {next_target} Pages…"
                    if target_pages == 10 else
                    f"{team_name} · Extension Jusqu’à {next_target} Pages…"
                ),
                progress=base_progress + int(progress_span * 0.10),
            )

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
    event_data_issues = []
    scanned_until = 0
    considered_matches = []

    for stage_limit in stages:
        if scan_completion_quantity(all_events, completion_mode) >= max_needed:
            break

        update_scan_job(
            job_id,
            status="running",
            message=(
                f"{team_name} · Scan Progressif Jusqu’à {stage_limit} matchs\n"
                f"Progression Trouvée : {round(scan_completion_quantity(all_events, completion_mode), 2)}/{max_needed}"
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
                    f"{team_name} · Événements Matchs {start + 1}-{batch_end}/{stage_limit}\n"
                    f"Progression Trouvée : {round(scan_completion_quantity(all_events, completion_mode), 2)}/{max_needed}"
                ),
                progress=base_progress + int(progress_span * (0.15 + 0.80 * stage_position)),
            )

            scanned = []

            max_workers = max(1, min(len(batch) or 1, INCIDENT_MAX_WORKERS))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}

                for idx, match in enumerate(batch):
                    future = executor.submit(get_incidents_json, f"event/{match['id']}/incidents")
                    futures[future] = (idx, match)

                for future in as_completed(futures):
                    idx, match = futures[future]

                    try:
                        data = future.result()
                    except Exception as e:
                        # Erreur réseau ou match incident indisponible : on ignore ce match
                        # au lieu de faire échouer tout le scan. Les 403/404 SofaScore sont
                        # attendus sur certains matchs, donc on ne les affiche qu'en debug.
                        err_text = str(e)
                        expected_web_gap = (
                            "challenge" in err_text
                            or "HTTP 403" in err_text
                            or "HTTP 404" in err_text
                            or "Not Found" in err_text
                        )
                        if SOFA_DEBUG_NETWORK or not expected_web_gap:
                            print(f"Match sans événements récupérés {match.get('id')}: {e}", file=sys.stderr)

                        issue_type = "missing" if ("HTTP 404" in err_text or "Not Found" in err_text) else ("blocked" if ("challenge" in err_text or "HTTP 403" in err_text) else "error")
                        issue = {
                            "id": match.get("id"),
                            "label": make_match_label(match),
                            "competition": get_competition_name(match),
                            "startTimestamp": match.get("startTimestamp") or 0,
                            "type": issue_type,
                            "reason": err_text,
                            "message": "Événements non récupérés pour ce match.",
                        }
                        scanned.append({
                            "idx": idx,
                            "match": match,
                            "events": [],
                            "issue": issue,
                            "matchUsed": {
                                "id": match.get("id"),
                                "label": make_match_label(match),
                                "count": 0,
                                "startTimestamp": match.get("startTimestamp") or 0,
                                "competition": get_competition_name(match),
                                "eventDataStatus": issue_type,
                                "eventDataIssue": True,
                                "error": err_text,
                            },
                        })
                        continue

                    data_issue = data.get("_footscanIssue") if isinstance(data, dict) else None
                    incidents = data.get("incidents") if isinstance(data, dict) else data

                    if not isinstance(incidents, list):
                        incidents = []

                    if data_issue:
                        issue = {
                            "id": match.get("id"),
                            "label": make_match_label(match),
                            "competition": get_competition_name(match),
                            "startTimestamp": match.get("startTimestamp") or 0,
                            "type": data_issue.get("type") or "blocked",
                            "reason": data_issue.get("reason") or data_issue.get("message") or "Événements non récupérés",
                            "message": data_issue.get("message") or "Événements non récupérés pour ce match.",
                        }
                    else:
                        issue = None

                    events = parse_incidents(incidents, match, analyzed_team_id)
                    scan_events = separate_mode_events(events) if direct_team_only else events

                    match_used = {
                        "id": match.get("id"),
                        "label": make_match_label(match),
                        "count": len(scan_events),
                        "startTimestamp": match.get("startTimestamp") or 0,
                        "competition": get_competition_name(match),
                        "eventDataStatus": "ok",
                    }

                    if data_issue:
                        match_used["eventDataStatus"] = data_issue.get("type") or "blocked"
                        match_used["eventDataIssue"] = True
                        match_used["error"] = data_issue.get("reason") or data_issue.get("message") or "Événements non récupérés"

                    scanned.append({
                        "idx": idx,
                        "match": match,
                        "events": scan_events,
                        "issue": issue,
                        "matchUsed": match_used,
                    })

            scanned.sort(key=lambda item: item["idx"])

            for item in scanned:
                # On ne compte les erreurs/ignorés que pour les matchs réellement
                # parcourus avant l'arrêt du scan. Les matchs récupérés en avance
                # dans le même batch ne doivent pas gonfler les compteurs.
                considered_matches.append(item.get("match") or {})

                if item.get("issue"):
                    event_data_issues.append(item["issue"])

                item_events = item["events"] or []

                if item_events:
                    all_events.extend(item_events)
                    matches_used.append(item["matchUsed"])

                    if direct_team_only:
                        renormalize_opponent_past_events(all_events, len(matches_used))

                if scan_completion_quantity(all_events, completion_mode) >= max_needed:
                    break

            scanned_until = batch_end

            if scan_completion_quantity(all_events, completion_mode) >= max_needed:
                break

    progression_found = round(scan_completion_quantity(all_events, completion_mode), 6)
    rank_reached = progression_found >= float(max_needed) - 1e-9

    issue_count = len(event_data_issues)

    # Ne pas afficher tous les matchs administratifs trouvés dans les pages Web :
    # cela donnait parfois des quantités abusives. On affiche seulement ceux qui
    # se situent dans la tranche temporelle réellement parcourue par le scan.
    if considered_matches:
        considered_timestamps = [m.get("startTimestamp") or 0 for m in considered_matches if isinstance(m, dict)]
        considered_timestamps = [ts for ts in considered_timestamps if ts]
    else:
        considered_timestamps = []

    if considered_timestamps:
        newest_considered = max(considered_timestamps)
        oldest_considered = min(considered_timestamps)
        administrative_source = [
            item for item in administrative_matches_ignored.values()
            if oldest_considered <= (item.get("startTimestamp") or 0) <= newest_considered
        ]
    else:
        administrative_source = []

    administrative_ignored = sorted(
        administrative_source,
        key=lambda item: (item.get("startTimestamp") or 0, item.get("id") or 0),
        reverse=True,
    )
    administrative_count = len(administrative_ignored)

    issue_parts = []
    if issue_count:
        issue_parts.append(f"⚠️ {issue_count} match(s) sans événements récupérés")
    if administrative_count:
        issue_parts.append(f"🚫 {administrative_count} match(s) administratif(s) ignoré(s)")
    if not rank_reached:
        issue_parts.append(f"⛔ progression insuffisante {round(progression_found, 2)}/{max_needed}")
    issue_note = " · " + " · ".join(issue_parts) if issue_parts else ""

    update_scan_job(
        job_id,
        status="running",
        message=f"{team_name} · Terminé ({len(all_events)} événements, Progression {round(scan_completion_quantity(all_events, completion_mode), 2)}, {len(matches_used)} matchs){issue_note}.",
        progress=base_progress + progress_span,
    )

    if issue_count:
        print(f"⚠️ {team_name}: {issue_count} match(s) sans événements récupérés. Résultat partiel pour cette équipe.")
    if administrative_count:
        print(f"🚫 {team_name}: {administrative_count} match(s) forfait/administratif(s) ignoré(s).")
    if not rank_reached:
        print(
            f"⛔ {team_name}: rang non atteint · progression {round(progression_found, 2)}/{max_needed} "
            f"après {pages_loaded_count}/{PAGES_TO_LOAD} pages et {len(matches_used)} match(s) utilisé(s)."
        )

    return {
        "events": all_events,
        "matchesUsed": matches_used,
        "eventDataIssues": event_data_issues,
        "eventDataIssueCount": issue_count,
        "administrativeMatchesIgnored": administrative_ignored,
        "administrativeMatchCount": administrative_count,
        "rankCoverage": {
            "reached": rank_reached,
            "progressionFound": progression_found,
            "progressionNeeded": float(max_needed),
            "missingProgression": round(max(0.0, float(max_needed) - progression_found), 6),
            "pagesLoaded": pages_loaded_count,
            "pagesAttempted": pages_attempted_count,
            "pagesLimit": PAGES_TO_LOAD,
            "matchesUsed": len(matches_used),
            "eventsFound": len(all_events),
        },
        "pagesLoaded": pages_loaded_count,
        "pagesAttempted": pages_attempted_count,
        "pagesLimit": PAGES_TO_LOAD,
        "scanPartial": bool(issue_count),
    }



def apply_simultaneous_match_minute_order(home_scan, away_scan, home_name="Domicile", away_name="Extérieur"):
    """Construit le mode simultané match par match puis minute par minute.

    Règle v128 validée :
    - flux domicile = événements directs du domicile + événements directs des
      adversaires passés de l'extérieur ;
    - flux extérieur = événements directs de l'extérieur + événements directs des
      adversaires passés du domicile.

    Important : on ne crée pas d'événement artificiel. Un événement adverse
    transféré est simplement remis dans le sens de l'équipe qui l'a vraiment
    produit : son signe est donc inversé par rapport au scan de départ.
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
        meta_by_id = {}

        for match in scan.get("matchesUsed") or []:
            match_id = match.get("id")
            if match_id is None:
                continue
            if match_id not in grouped:
                order.append(match_id)
            grouped.setdefault(match_id, [])
            meta_by_id[match_id] = match

        for event in scan.get("events") or []:
            match_id = event.get("matchId")
            grouped.setdefault(match_id, []).append(event)
            if match_id not in order:
                order.append(match_id)
            if match_id not in meta_by_id:
                meta_by_id[match_id] = {
                    "id": match_id,
                    "label": event.get("match") or "Match",
                    "competition": event.get("competition") or "Toutes compétitions",
                    "startTimestamp": event.get("startTimestamp") or 0,
                }

        return order, grouped, meta_by_id

    def copy_for_target(event, target_key, source_key, source_name, target_name, linked_from_opponent):
        copied = dict(event)
        clean_detail = strip_camp_prefix(copied.get("detail"))

        copied["targetName"] = target_name
        copied["simultaneousTarget"] = target_key
        copied["simultaneousSourceKey"] = source_key
        copied["sourceMatchId"] = copied.get("matchId")
        copied["displaySide"] = f"Attribué à {target_name}"

        if linked_from_opponent:
            try:
                copied["value"] = round(-float(copied.get("value", 0)), 4)
            except Exception:
                copied["value"] = copied.get("value")

            copied["side"] = "team"
            copied["linkedFromOpponentPast"] = True
            copied["opponentPastWeighted"] = True
            copied["opponentPastDivisor"] = 1
            copied["weight"] = 1
            copied["originLabel"] = f"adversaire passé de {source_name}"
            copied["detail"] = f"Attribué à {target_name} · origine: adversaire passé de {source_name} · {clean_detail}"
        else:
            copied["side"] = "team"
            copied["linkedFromOpponentPast"] = False
            copied["opponentPastWeighted"] = False
            copied["opponentPastDivisor"] = 1
            copied["weight"] = 1
            copied["originLabel"] = f"passé direct de {target_name}"
            copied["detail"] = f"Attribué à {target_name} · origine: passé direct · {clean_detail}"

        return copied

    home_order, home_grouped, home_meta_by_id = group_by_match(home_scan)
    away_order, away_grouped, away_meta_by_id = group_by_match(away_scan)

    # Les diviseurs simultanés ne sont pas globaux. Ils sont recalculés
    # plus bas pour chaque flux cible :
    # - rangs de A => adversaires passés de B ÷ matchs B utilisés pour A ;
    # - rangs de B => adversaires passés de A ÷ matchs A utilisés pour B.

    def attach_match_meta(event, meta):
        if not meta:
            return event
        event["competition"] = meta.get("competition") or event.get("competition") or "Toutes compétitions"
        event["sourceCompetition"] = event["competition"]
        event["startTimestamp"] = meta.get("startTimestamp") or event.get("startTimestamp") or 0
        event["sourceStartTimestamp"] = event["startTimestamp"]
        return event

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
            return (-(minute + added), 0 if source_key == "home" else 1, original_index)

        for source_key, original_index, event in sorted(items, key=sort_key):
            side = event.get("side")
            if side not in {"team", "opponent"}:
                continue

            shared_index += 1

            if source_key == "home":
                if side == "opponent":
                    # Adversaire passé du domicile -> flux extérieur.
                    copied = copy_for_target(event, "away", "home", home_name, away_name, True)
                    copied = attach_match_meta(copied, home_meta_by_id.get(event.get("matchId")))
                    away_events.append(copied)
                else:
                    copied = copy_for_target(event, "home", "home", home_name, home_name, False)
                    copied = attach_match_meta(copied, home_meta_by_id.get(event.get("matchId")))
                    home_events.append(copied)
            else:
                if side == "opponent":
                    # Adversaire passé de l'extérieur -> flux domicile.
                    copied = copy_for_target(event, "home", "away", away_name, home_name, True)
                    copied = attach_match_meta(copied, away_meta_by_id.get(event.get("matchId")))
                    home_events.append(copied)
                else:
                    copied = copy_for_target(event, "away", "away", away_name, away_name, False)
                    copied = attach_match_meta(copied, away_meta_by_id.get(event.get("matchId")))
                    away_events.append(copied)

            copied["simultaneousIndex"] = shared_index
            copied["simultaneousMatchPair"] = match_index + 1
            combined_events.append(dict(copied))

    combined_events.sort(key=lambda event: event.get("simultaneousIndex") or 0)

    home_result = dict(home_scan)
    away_result = dict(away_scan)
    home_result["events"] = home_events
    away_result["events"] = away_events
    home_result["simultaneousLinkedMode"] = True
    away_result["simultaneousLinkedMode"] = True

    return home_result, away_result, combined_events


def trend_result_style(value):
    """Convertit une tendance numérique en style résultat V/N/D."""
    try:
        value = float(value)
    except Exception:
        value = 0.0
    if value > 0:
        return "V"
    if value < 0:
        return "D"
    return "N"


def trend_label_from_style(style):
    return {"V": "Victoire", "N": "Nul", "D": "Défaite"}.get(style, "—")


def trend_average(values):
    clean = []
    for value in values or []:
        try:
            n = float(value)
        except Exception:
            continue
        if math.isfinite(n):
            clean.append(n)
    return sum(clean) / len(clean) if clean else 1.0


def trend_goal_chrono_key(minute, added=0):
    """Clé de chronologie réelle d'un but pour la reconstitution.

    On compare d'abord la période, puis la minute et enfin le temps additionnel.
    Ainsi 45+3 reste avant 46, car toute la 1re mi-temps reste avant la 2e.
    """
    try:
        minute_value = int(minute)
    except Exception:
        minute_value = 0

    try:
        added_value = int(added or 0)
    except Exception:
        added_value = 0

    if minute_value <= 0:
        return (0, 0, 0)

    period = 1 if minute_value <= 45 else 2
    return (period, minute_value, added_value)


def trend_goal_average_minute(minute, added=0):
    try:
        minute_value = float(minute)
    except Exception:
        minute_value = 1.0

    try:
        added_value = float(added or 0)
    except Exception:
        added_value = 0.0

    return minute_value + added_value


def trend_goal_minute_label(minute, added=0):
    try:
        minute_value = int(minute)
    except Exception:
        minute_value = 0

    try:
        added_value = int(added or 0)
    except Exception:
        added_value = 0

    return f"{minute_value}+{added_value}'" if added_value else f"{minute_value}'"


def safe_score_value(value):
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except Exception:
        return None


def match_score_pair(match):
    """Retourne le score final fiable du match source quand il existe.

    On privilégie le score de temps réglementaire quand SofaScore le fournit,
    sinon le score courant/final. Ce score sert uniquement à vérifier qu'un
    0-0 est réel et que les incidents récupérés contiennent les buts du match.
    """
    home_score = match.get("homeScore") or {}
    away_score = match.get("awayScore") or {}

    for key in ("normaltime", "current", "display"):
        home = safe_score_value(home_score.get(key))
        away = safe_score_value(away_score.get(key))
        if home is not None and away is not None:
            return home, away

    return None, None


def match_score_total(match):
    home, away = match_score_pair(match)
    if home is None or away is None:
        return None
    return max(0, home) + max(0, away)


def reconstruction_source_is_complete(source_record):
    if not isinstance(source_record, dict):
        return False
    if source_record.get("eventDataIssue"):
        return False
    if source_record.get("reconstructionGoalsIncomplete"):
        return False
    return True


def collect_reconstruction_goal_entries(match, incidents, analyzed_team_id):
    """Prépare les buts d'un match source pour la reconstitution diagonale.

    Chaque match source fournit ensuite un seul élément selon sa position dans
    l'historique: dernier but, avant-dernier but, etc. Si cet élément n'existe
    pas, on ignore ce match source. Le 0-0 est conservé uniquement quand le
    match source est réellement sans but.
    """
    match_label = make_match_label(match)
    match_id = match.get("id")
    competition = get_competition_name(match)
    start_timestamp = match.get("startTimestamp") or 0
    final_home_score, final_away_score = match_score_pair(match)
    final_score_total = match_score_total(match)
    true_zero_zero = final_score_total == 0 if final_score_total is not None else False
    source_score_label = f"{final_home_score}-{final_away_score}" if final_home_score is not None and final_away_score is not None else "Score inconnu"
    match_has_assists = match_contains_goal_assist(incidents)
    goals = []

    for inc in incidents or []:
        if not isinstance(inc, dict) or inc.get("incidentType") != "goal":
            continue

        minute = inc.get("time")
        added = inc.get("addedTime") or 0
        if minute is None or minute < 1 or minute > 90:
            continue

        own_goal = is_own_goal_incident(inc)
        if own_goal:
            goal_for_team = not own_goal_committed_by_analyzed_team(inc, match, analyzed_team_id)
            attack_delta = 0
            opponent_attack_delta = 0
        else:
            scorer_is_analyzed = incident_belongs_to_analyzed_team(inc, match, analyzed_team_id)
            goal_for_team = scorer_is_analyzed
            attack_delta = 1 if scorer_is_analyzed else 0
            opponent_attack_delta = 0 if scorer_is_analyzed else 1

        goals.append({
            "isZeroZero": False,
            "minute": int(minute),
            "added": int(added or 0),
            "minuteLabel": trend_goal_minute_label(minute, added),
            "averageMinute": trend_goal_average_minute(minute, added),
            "chronoKey": trend_goal_chrono_key(minute, added),
            "goalDelta": 1 if goal_for_team else -1,
            "attackDelta": attack_delta,
            "opponentAttackDelta": opponent_attack_delta,
            "goalForTeam": bool(goal_for_team),
            "ownGoal": bool(own_goal),
            "sourceMatchId": match_id,
            "sourceLabel": match_label,
            "sourceCompetition": competition,
            "sourceStartTimestamp": start_timestamp,
            "sourceScoreLabel": source_score_label,
            "finalHomeScore": final_home_score,
            "finalAwayScore": final_away_score,
            "matchHasAssists": match_has_assists,
            "assistDataStatus": "assist-found" if match_has_assists else "no-assist-found",
        })

    goals.sort(key=lambda item: item.get("chronoKey") or (0, 0, 0))
    goal_data_complete = True
    if final_score_total is not None and final_score_total > len(goals):
        goal_data_complete = False

    zero_zero = {
        "isZeroZero": True,
        "minute": 1,
        "added": 0,
        "minuteLabel": "0-0",
        "averageMinute": 1.0,
        "chronoKey": (0, 1, 0),
        "goalDelta": 0,
        "attackDelta": 0,
        "opponentAttackDelta": 0,
        "goalForTeam": None,
        "ownGoal": False,
        "sourceMatchId": match_id,
        "sourceLabel": match_label,
        "sourceCompetition": competition,
        "sourceStartTimestamp": start_timestamp,
        "sourceScoreLabel": source_score_label,
        "finalHomeScore": final_home_score,
        "finalAwayScore": final_away_score,
        "matchHasAssists": match_has_assists,
        "assistDataStatus": "assist-found" if match_has_assists else "no-assist-found",
    }

    return {
        "match": match,
        "id": match_id,
        "label": match_label,
        "competition": competition,
        "startTimestamp": start_timestamp,
        "goals": goals,
        "zeroZero": zero_zero,
        "trueZeroZero": bool(true_zero_zero),
        "finalHomeScore": final_home_score,
        "finalAwayScore": final_away_score,
        "finalScoreTotal": final_score_total,
        "reconstructionGoalsIncomplete": not goal_data_complete,
        "matchHasAssists": match_has_assists,
        "assistDataStatus": "assist-found" if match_has_assists else "no-assist-found",
    }


def reconstruction_source_is_true_zero_zero(source_record):
    if not reconstruction_source_is_complete(source_record):
        return False
    return bool(source_record.get("trueZeroZero"))


def reconstruction_source_entry(source_record, goal_index_from_end):
    if not reconstruction_source_is_complete(source_record):
        return None

    goals = source_record.get("goals") or []
    needed_from_end = max(1, int(goal_index_from_end or 1))

    if len(goals) >= needed_from_end:
        entry = dict(goals[-needed_from_end])
    elif needed_from_end == 1 and reconstruction_source_is_true_zero_zero(source_record):
        entry = dict(source_record.get("zeroZero") or {})
    else:
        return None

    entry["reconstructionSourceIndex"] = needed_from_end
    entry["reconstructionSourceGoalCount"] = len(goals)
    return entry


def reconstruction_entry_keeps_reverse_chronology(previous_entry, next_entry):
    """La reconstitution remonte le match: le prochain but doit être antérieur.

    Une minute de 1re mi-temps en temps additionnel reste donc valide après un
    but de 2e mi-temps, par exemple 46 puis 45+3.
    """
    if not previous_entry or not next_entry:
        return True

    previous_key = previous_entry.get("chronoKey") or (0, 0, 0)
    next_key = next_entry.get("chronoKey") or (0, 0, 0)
    return next_key <= previous_key


def compact_reconstruction_label(entries):
    usable = [entry for entry in entries or [] if isinstance(entry, dict)]
    if not usable:
        return "Match reconstitué"

    first = usable[0].get("sourceLabel") or "Match"
    last = usable[-1].get("sourceLabel") or first

    if first == last:
        return first

    return f"{last} → {first}"


def build_reconstructed_trend_sample(entries, analyzed_team_id, level_mode="full", index=1):
    clean_entries = [entry for entry in entries or [] if isinstance(entry, dict)]
    zero_only = len(clean_entries) == 1 and bool(clean_entries[0].get("isZeroZero"))
    non_zero_entries = [entry for entry in clean_entries if not entry.get("isZeroZero")]

    goals_for = sum(1 for entry in non_zero_entries if entry.get("goalDelta") == 1)
    goals_against = sum(1 for entry in non_zero_entries if entry.get("goalDelta") == -1)
    attack_goals_for = sum(int(entry.get("attackDelta") or 0) for entry in non_zero_entries)
    opponent_attack_goals = sum(int(entry.get("opponentAttackDelta") or 0) for entry in non_zero_entries)

    all_goal_minutes = [float(entry.get("averageMinute") or 1.0) for entry in non_zero_entries]
    attack_goal_minutes = [float(entry.get("averageMinute") or 1.0) for entry in non_zero_entries if int(entry.get("attackDelta") or 0) > 0]
    opponent_attack_minutes = [float(entry.get("averageMinute") or 1.0) for entry in non_zero_entries if int(entry.get("opponentAttackDelta") or 0) > 0]

    if level_mode == "attack":
        level = attack_goals_for
        minutes_for_average = attack_goal_minutes[:] if attack_goal_minutes else [1.0]
    else:
        level = goals_for - goals_against
        minutes_for_average = all_goal_minutes[:] if all_goal_minutes else [1.0]

    label = compact_reconstruction_label(clean_entries)
    first_entry = clean_entries[0] if clean_entries else {}
    last_entry = clean_entries[-1] if clean_entries else first_entry
    source_ids = [str(entry.get("sourceMatchId")) for entry in clean_entries if entry.get("sourceMatchId") is not None]
    sample_id = f"reconstitution-{analyzed_team_id}-{index}-" + "-".join(source_ids[:4])

    match_has_assists = any(bool(entry.get("matchHasAssists")) for entry in clean_entries)
    assist_status = "assist-found" if match_has_assists else "no-assist-found"
    opponent_minutes_for_average = opponent_attack_minutes[:] if opponent_attack_minutes else [1.0]
    if level_mode == "attack":
        # Camp combiné = attaque uniquement. Le score final affiché de la
        # reconstitution doit donc être le total offensif, jamais un score
        # complet type 1-1 qui ferait croire à attaque + défense.
        reconstruction_score_label = f"Attaque {attack_goals_for}"
        reconstruction_display_label = f"Reconstitution {index}"
    else:
        reconstruction_score_label = f"{goals_for}-{goals_against}"
        reconstruction_display_label = f"Reconstitution {index} · {reconstruction_score_label}"
    reconstruction_full_score_label = f"{goals_for}-{goals_against}"
    reconstruction_attack_score_label = f"Attaque {attack_goals_for}"
    opponent_attack_score_label = f"Attaque adverse {opponent_attack_goals}"

    return {
        "id": sample_id,
        "label": label,
        "reconstructionLabel": label,
        "reconstructionDisplayLabel": reconstruction_display_label,
        "reconstructionScoreLabel": reconstruction_score_label,
        "reconstructionFullScoreLabel": reconstruction_full_score_label,
        "reconstructionAttackScoreLabel": reconstruction_attack_score_label,
        "competition": first_entry.get("sourceCompetition") or last_entry.get("sourceCompetition") or "Reconstitution",
        "startTimestamp": first_entry.get("sourceStartTimestamp") or last_entry.get("sourceStartTimestamp") or 0,
        "homeTeam": {},
        "awayTeam": {},
        "analyzedTeamId": analyzed_team_id,
        "goalsFor": goals_for,
        "goalsAgainst": goals_against,
        "attackGoalsFor": attack_goals_for,
        "level": level,
        "levelMode": level_mode,
        "resultStyle": trend_result_style(level),
        "resultLabel": trend_label_from_style(trend_result_style(level)),
        "goalMinutes": all_goal_minutes,
        "attackGoalMinutes": attack_goal_minutes,
        "minutesForAverage": minutes_for_average,
        "averageMinute": round(trend_average(minutes_for_average), 4),
        "matchHasAssists": match_has_assists,
        "assistDataStatus": assist_status,
        "eventDataStatus": "ok",
        "reconstructedMatch": True,
        "reconstructionMethod": "diagonal_last_goal_reverse_chronology",
        "reconstructionIndex": index,
        "reconstructionZeroOnly": zero_only,
        "reconstructionEntries": [
            {
                "sourceMatchId": entry.get("sourceMatchId"),
                "sourceLabel": entry.get("sourceLabel"),
                "sourceCompetition": entry.get("sourceCompetition"),
                "sourceStartTimestamp": entry.get("sourceStartTimestamp") or 0,
                "sourceScoreLabel": entry.get("sourceScoreLabel"),
                "finalHomeScore": entry.get("finalHomeScore"),
                "finalAwayScore": entry.get("finalAwayScore"),
                "matchHasAssists": entry.get("matchHasAssists"),
                "assistDataStatus": entry.get("assistDataStatus"),
                "minuteLabel": entry.get("minuteLabel"),
                "minute": entry.get("minute"),
                "added": entry.get("added"),
                "isZeroZero": bool(entry.get("isZeroZero")),
                "goalDelta": entry.get("goalDelta"),
                "attackDelta": entry.get("attackDelta"),
                "opponentAttackDelta": entry.get("opponentAttackDelta"),
                "reconstructionSourceIndex": entry.get("reconstructionSourceIndex"),
            }
            for entry in clean_entries
        ],
        "opponentAttack": {
            "id": f"{sample_id}-opponent-attack",
            "label": label,
            "reconstructionLabel": label,
            "reconstructionDisplayLabel": reconstruction_display_label,
            "reconstructionScoreLabel": opponent_attack_score_label,
            "competition": first_entry.get("sourceCompetition") or last_entry.get("sourceCompetition") or "Reconstitution",
            "startTimestamp": first_entry.get("sourceStartTimestamp") or last_entry.get("sourceStartTimestamp") or 0,
            "level": opponent_attack_goals,
            "attackGoalsFor": opponent_attack_goals,
            "minutesForAverage": opponent_minutes_for_average,
            "averageMinute": round(trend_average(opponent_minutes_for_average), 4),
            "matchHasAssists": match_has_assists,
            "assistDataStatus": assist_status,
            "reconstructedMatch": True,
            "reconstructionEntries": [
                {
                    "sourceMatchId": entry.get("sourceMatchId"),
                    "sourceLabel": entry.get("sourceLabel"),
                    "sourceCompetition": entry.get("sourceCompetition"),
                    "sourceStartTimestamp": entry.get("sourceStartTimestamp") or 0,
                    "sourceScoreLabel": entry.get("sourceScoreLabel"),
                    "minuteLabel": entry.get("minuteLabel"),
                    "isZeroZero": bool(entry.get("isZeroZero")),
                    "opponentAttackDelta": entry.get("opponentAttackDelta"),
                    "matchHasAssists": entry.get("matchHasAssists"),
                    "assistDataStatus": entry.get("assistDataStatus"),
                }
                for entry in clean_entries
            ],
        },
    }


def build_reconstructed_trend_samples(source_records, analyzed_team_id, level_mode="full"):
    """Reconstruit des matchs uniquement à partir de vrais matchs source.

    Règles appliquées pour chaque camp et chaque mode de calcul :
    - un nouveau match reconstitué démarre avec un vrai dernier but source ;
    - la suite utilise l'avant-dernier but du match source suivant, puis le
      troisième depuis la fin, etc. ;
    - si le but trouvé casse la chronologie réelle, le match en cours est
      clôturé et ce but démarre le match suivant ;
    - un vrai 0-0 démarre et clôture immédiatement un match ;
    - un match dont les buts ne sont pas récupérés complètement n'est pas
      utilisé pour fabriquer un faux N 0.
    """
    samples = []
    current = []
    previous_entry = None
    source_index = 0
    goal_index_from_end = 1

    def close_current():
        nonlocal current, previous_entry, goal_index_from_end
        if current:
            samples.append(build_reconstructed_trend_sample(
                current,
                analyzed_team_id,
                level_mode=level_mode,
                index=len(samples) + 1,
            ))
        current = []
        previous_entry = None
        goal_index_from_end = 1

    records = list(source_records or [])

    while source_index < len(records):
        source_record = records[source_index]

        if not reconstruction_source_is_complete(source_record):
            close_current()
            source_index += 1
            continue

        if reconstruction_source_is_true_zero_zero(source_record):
            close_current()
            zero_entry = reconstruction_source_entry(source_record, 1)
            if zero_entry:
                samples.append(build_reconstructed_trend_sample(
                    [zero_entry],
                    analyzed_team_id,
                    level_mode=level_mode,
                    index=len(samples) + 1,
                ))
            source_index += 1
            goal_index_from_end = 1
            continue

        entry = reconstruction_source_entry(source_record, goal_index_from_end)

        if not entry:
            # Le match source n'a pas le but demandé. On clôture le match en
            # cours puis on repart de ce même match source avec son dernier but,
            # afin de rester sur des vrais matchs au lieu d'inventer un 0-0.
            if current:
                close_current()
                continue
            source_index += 1
            goal_index_from_end = 1
            continue

        if current and not reconstruction_entry_keeps_reverse_chronology(previous_entry, entry):
            # Le but existe mais casse l'ordre chronologique : il clôture le
            # match en cours et devient le début du match suivant.
            close_current()
            current = [entry]
            previous_entry = entry
            source_index += 1
            goal_index_from_end = 2
            continue

        current.append(entry)
        previous_entry = entry
        source_index += 1
        goal_index_from_end += 1

    close_current()
    return samples

def truthy_param(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "oui"}
    return False


def trend_match_sample(match, incidents, analyzed_team_id, level_mode="full"):
    """Construit le niveau d'un match pour le système Tendance.

    level_mode="full" : niveau = buts marqués - buts encaissés.
    level_mode="attack" : niveau = buts offensifs uniquement, sans défense.

    Important pour le mode séparé : un CSC adverse qui profite à l'équipe
    n'est pas considéré comme une attaque de cette équipe. Les prolongations
    et tirs au but restent exclus via le filtre minute 1-90. Un match sans
    but utile est représenté comme une occurrence neutre minute 1.
    """
    goals_for = 0
    goals_against = 0
    attack_goals_for = 0
    all_goal_minutes = []
    attack_goal_minutes = []
    match_has_assists = match_contains_goal_assist(incidents)

    for inc in incidents or []:
        if not isinstance(inc, dict) or inc.get("incidentType") != "goal":
            continue

        minute = inc.get("time")
        added = inc.get("addedTime") or 0
        if minute is None or minute < 1 or minute > 90:
            continue

        event_minute = float(minute) + float(added or 0)
        all_goal_minutes.append(event_minute)

        own_goal = is_own_goal_incident(inc)
        if own_goal:
            goal_for_team = not own_goal_committed_by_analyzed_team(inc, match, analyzed_team_id)
        else:
            goal_for_team = incident_belongs_to_analyzed_team(inc, match, analyzed_team_id)

        if goal_for_team:
            goals_for += 1
        else:
            goals_against += 1

        # Attaque pure : uniquement les buts non-CSC attribués au camp analysé.
        if not own_goal and incident_belongs_to_analyzed_team(inc, match, analyzed_team_id):
            attack_goals_for += 1
            attack_goal_minutes.append(event_minute)

    # Technique v179 : chaque score existant compte dans la moyenne minute.
    # Le score initial 0-0 existe dans tous les matchs à la minute 1.
    # On l'ajoute donc systématiquement, même quand il y a ensuite des buts.
    if level_mode == "attack":
        level = attack_goals_for
        minutes_for_average = [1.0] + attack_goal_minutes[:]
    else:
        level = goals_for - goals_against
        minutes_for_average = [1.0] + all_goal_minutes[:]

    return {
        "id": match.get("id"),
        "label": make_match_label(match),
        "competition": get_competition_name(match),
        "startTimestamp": match.get("startTimestamp") or 0,
        "homeTeam": match.get("homeTeam") or {},
        "awayTeam": match.get("awayTeam") or {},
        "analyzedTeamId": analyzed_team_id,
        "goalsFor": goals_for,
        "goalsAgainst": goals_against,
        "attackGoalsFor": attack_goals_for,
        "level": level,
        "levelMode": level_mode,
        "resultStyle": trend_result_style(level),
        "resultLabel": trend_label_from_style(trend_result_style(level)),
        "goalMinutes": all_goal_minutes,
        "attackGoalMinutes": attack_goal_minutes,
        "minutesForAverage": minutes_for_average,
        "averageMinute": round(trend_average(minutes_for_average), 4),
        "matchHasAssists": match_has_assists,
        "assistDataStatus": "assist-found" if match_has_assists else "no-assist-found",
        "eventDataStatus": "ok",
    }


def trend_opponent_team_id(match, analyzed_team_id):
    home_id = ((match.get("homeTeam") or {}).get("id"))
    away_id = ((match.get("awayTeam") or {}).get("id"))
    if home_id == analyzed_team_id:
        return away_id
    if away_id == analyzed_team_id:
        return home_id
    return None


def build_separated_offensive_samples(primary_samples, opposite_samples, side_key):
    """Construit le mode séparé offensif vs offensif aligné par ligne.

    Pour A ligne N : attaque A ligne N + attaque de l'adversaire passé de B ligne N.
    Pour B ligne N : attaque B ligne N + attaque de l'adversaire passé de A ligne N.
    Le simultané n'utilise pas cette fonction et reste en attaque + défense.
    """
    combined = []
    total = min(len(primary_samples or []), len(opposite_samples or []))

    for idx in range(total):
        direct = primary_samples[idx] or {}
        source = opposite_samples[idx] or {}
        opponent_attack = source.get("opponentAttack") or {}

        direct_level = float(direct.get("level") or 0)
        adv_level = float(opponent_attack.get("level") or 0)
        level = direct_level + adv_level

        direct_minutes = list(direct.get("minutesForAverage") or [1.0])
        adv_minutes = list(opponent_attack.get("minutesForAverage") or [1.0])
        minutes_for_average = direct_minutes + adv_minutes

        direct_score_label = direct.get("reconstructionAttackScoreLabel") or direct.get("reconstructionScoreLabel") or format(level, ".6g")
        opponent_score_label = opponent_attack.get("reconstructionScoreLabel") or f"Attaque adverse {format(adv_level, '.6g')}"
        combined_formula_label = f"{direct_score_label} + {opponent_score_label}"
        combined_score_label = f"Attaque {format(level, '.6g')}"
        reconstruction_index = direct.get("reconstructionIndex") or (idx + 1)

        sample = {
            **direct,
            "id": direct.get("id"),
            "label": direct.get("label"),
            "reconstructionLabel": f"Reconstitution {reconstruction_index}",
            "reconstructionDisplayLabel": f"Reconstitution {reconstruction_index}",
            "reconstructionScoreLabel": combined_score_label,
            "reconstructionFormulaLabel": combined_formula_label,
            "directReconstructionScoreLabel": direct_score_label,
            "opponentReconstructionScoreLabel": opponent_score_label,
            "competition": direct.get("competition"),
            "startTimestamp": direct.get("startTimestamp") or 0,
            "level": round(level, 6),
            "levelMode": "separated-attack-vs-attack",
            "resultStyle": trend_result_style(level),
            "resultLabel": trend_label_from_style(trend_result_style(level)),
            "minutesForAverage": minutes_for_average,
            "averageMinute": round(trend_average(minutes_for_average), 4),
            "directAttackLevel": round(direct_level, 6),
            "opponentAttackLevel": round(adv_level, 6),
            "opponentAttackSource": {
                "id": source.get("id"),
                "label": source.get("label"),
                "reconstructionLabel": source.get("reconstructionLabel") or source.get("label"),
                "reconstructionDisplayLabel": source.get("reconstructionDisplayLabel") or source.get("label"),
                "reconstructionScoreLabel": opponent_score_label,
                "competition": source.get("competition"),
                "startTimestamp": source.get("startTimestamp") or 0,
                "level": round(adv_level, 6),
                "minutesForAverage": adv_minutes,
                "averageMinute": round(trend_average(adv_minutes), 4),
                "matchHasAssists": opponent_attack.get("matchHasAssists", source.get("matchHasAssists")),
                "assistDataStatus": opponent_attack.get("assistDataStatus", source.get("assistDataStatus")),
                "reconstructionEntries": opponent_attack.get("reconstructionEntries") or source.get("reconstructionEntries") or [],
            },
            "analysisFormula": "attaque équipe + attaque adversaire du camp opposé",
            "analysisFormulaLabel": combined_formula_label,
            "analysisLine": idx + 1,
            "side": side_key,
        }
        combined.append(sample)

    return combined


def _source_match_rows_from_reconstruction_entries(entries, role_label=None):
    rows = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        match_id = entry.get("sourceMatchId")
        label = entry.get("sourceLabel") or "Match source"
        key = str(match_id) if match_id is not None else f"{label}-{entry.get('sourceStartTimestamp') or 0}"
        rows.append({
            "key": key,
            "id": match_id,
            "label": label,
            "competition": entry.get("sourceCompetition") or "Toutes compétitions",
            "startTimestamp": entry.get("sourceStartTimestamp") or 0,
            "sourceScoreLabel": entry.get("sourceScoreLabel") or "Score inconnu",
            "minuteLabel": entry.get("minuteLabel") or ("0-0" if entry.get("isZeroZero") else "—"),
            "isZeroZero": bool(entry.get("isZeroZero")),
            "matchHasAssists": entry.get("matchHasAssists"),
            "assistDataStatus": entry.get("assistDataStatus"),
            "roleLabel": role_label or "Reconstitution",
        })
    return rows


def build_reconstruction_source_matches_used(samples):
    """Liste les vrais matchs source utilisés, pas les reconstitutions affichées."""
    grouped = {}
    order = []
    for sample in samples or []:
        if not isinstance(sample, dict):
            continue
        rows = _source_match_rows_from_reconstruction_entries(sample.get("reconstructionEntries") or [], role_label="Reconstitution directe")
        opponent_source = sample.get("opponentAttackSource") or {}
        rows.extend(_source_match_rows_from_reconstruction_entries(opponent_source.get("reconstructionEntries") or [], role_label="Reconstitution opposée"))
        for row in rows:
            key = row.get("key")
            if key not in grouped:
                grouped[key] = {
                    "id": row.get("id"),
                    "label": row.get("label"),
                    "count": 0,
                    "usedCount": 0,
                    "startTimestamp": row.get("startTimestamp") or 0,
                    "competition": row.get("competition") or "Toutes compétitions",
                    "eventDataStatus": "ok",
                    "sourceScoreLabel": row.get("sourceScoreLabel") or "Score inconnu",
                    "minutesUsed": [],
                    "roles": [],
                    "matchHasAssists": row.get("matchHasAssists"),
                    "assistDataStatus": row.get("assistDataStatus"),
                    "usedInReconstruction": True,
                }
                order.append(key)
            item = grouped[key]
            item["count"] += 1
            item["usedCount"] += 1
            minute_label = row.get("minuteLabel")
            if minute_label and minute_label not in item["minutesUsed"]:
                item["minutesUsed"].append(minute_label)
            role_label = row.get("roleLabel")
            if role_label and role_label not in item["roles"]:
                item["roles"].append(role_label)
            if item.get("assistDataStatus") != "assist-found" and row.get("assistDataStatus") == "assist-found":
                item["assistDataStatus"] = "assist-found"
                item["matchHasAssists"] = True
    return sorted((grouped[key] for key in order), key=lambda item: (item.get("startTimestamp") or 0, item.get("id") or 0), reverse=True)


def rebuild_trend_matches_used_from_samples(samples):
    source_matches = build_reconstruction_source_matches_used(samples)
    if source_matches:
        return source_matches
    return [
        {
            "id": sample.get("id"),
            "label": sample.get("label"),
            "count": abs(sample.get("level") or 0),
            "startTimestamp": sample.get("startTimestamp") or 0,
            "competition": sample.get("competition") or "Toutes compétitions",
            "eventDataStatus": sample.get("eventDataStatus") or "ok",
            "trendLevel": sample.get("level"),
            "trendAverageMinute": sample.get("averageMinute"),
            "matchHasAssists": sample.get("matchHasAssists"),
            "assistDataStatus": sample.get("assistDataStatus"),
            "directAttackLevel": sample.get("directAttackLevel"),
            "opponentAttackLevel": sample.get("opponentAttackLevel"),
            "opponentAttackSource": sample.get("opponentAttackSource"),
            "analysisFormula": sample.get("analysisFormula"),
            "analysisLine": sample.get("analysisLine"),
        }
        for sample in samples or []
    ]


def fetch_trend_team_matches(job_id, analyzed_team_id, skip, trend_count, team_name, base_progress, progress_span, level_mode="full"):
    needed_matches = max(2, int(trend_count) + 1)
    pages = []
    stopped_history = False
    administrative_matches_ignored = {}
    pages_loaded_count = 0
    pages_attempted_count = 0

    def build_finished_matches():
        by_id = {}
        for match in pages:
            if not isinstance(match, dict):
                continue
            match_id = match.get("id")
            if not match_id:
                continue
            home_id = (match.get("homeTeam") or {}).get("id")
            away_id = (match.get("awayTeam") or {}).get("id")
            if home_id != analyzed_team_id and away_id != analyzed_team_id:
                continue
            admin_reason = administrative_match_reason(match)
            if admin_reason:
                administrative_matches_ignored[match_id] = make_administrative_match_issue(match, admin_reason)
                continue
            by_id[match_id] = match
        return by_id

    page_targets = [step for step in PAGE_LOAD_STEPS if step <= PAGES_TO_LOAD]
    if PAGES_TO_LOAD not in page_targets:
        page_targets.append(PAGES_TO_LOAD)

    next_page = 0
    by_id = {}

    def load_until_required(required_count):
        nonlocal next_page, by_id, stopped_history, pages_loaded_count, pages_attempted_count

        for target_pages in page_targets:
            if target_pages <= next_page:
                continue
            if stopped_history:
                break

            for page in range(next_page, target_pages):
                update_scan_job(
                    job_id,
                    status="running",
                    message=f"{team_name} · Tendance · Page {page + 1}/{target_pages}",
                    progress=base_progress + int(progress_span * 0.12 * ((page + 1) / max(1, target_pages))),
                )
                pages_attempted_count = max(pages_attempted_count, page + 1)
                try:
                    data = get_json(f"team/{analyzed_team_id}/events/last/{page}")
                except Exception as e:
                    error_text = str(e)
                    if "HTTP 404" in error_text or "Not Found" in error_text:
                        stopped_history = True
                        break
                    if pages:
                        stopped_history = True
                        break
                    raise

                page_events = data.get("events") if isinstance(data, dict) else data
                if isinstance(page_events, list) and page_events:
                    pages.extend(page_events)
                    pages_loaded_count = max(pages_loaded_count, page + 1)
                else:
                    stopped_history = True
                    break

            next_page = max(next_page, target_pages)
            by_id = build_finished_matches()
            if len(by_id) >= required_count:
                break

        by_id = build_finished_matches()
        return by_id

    event_data_issues = []
    source_records = []
    reconstructed_samples = []
    samples = []
    initial_buffer = max(24, min(180, needed_matches * 10))
    growth_step = max(12, min(120, needed_matches * 6))
    required = skip + needed_matches + initial_buffer

    while True:
        by_id = load_until_required(required)
        sorted_matches = sorted(by_id.values(), key=lambda m: (m.get("startTimestamp") or 0, m.get("id") or 0), reverse=True)
        selected_matches = sorted_matches[skip:required]
        total_sources = len(selected_matches)

        if total_sources < needed_matches and (stopped_history or next_page >= PAGES_TO_LOAD):
            raise RuntimeError(f"{team_name}: pas assez de matchs valides pour {trend_count} tendances ({total_sources}/{needed_matches}).")

        for idx in range(len(source_records), total_sources):
            match = selected_matches[idx]
            update_scan_job(
                job_id,
                status="running",
                message=f"{team_name} · Tendance · Source {idx + 1}/{total_sources}",
                progress=base_progress + int(progress_span * (0.15 + 0.80 * ((idx + 1) / max(1, total_sources)))),
            )
            data = get_incidents_json(f"event/{match['id']}/incidents")
            issue = data.get("_footscanIssue") if isinstance(data, dict) else None
            incidents = data.get("incidents") if isinstance(data, dict) else data
            if not isinstance(incidents, list):
                incidents = []
            source_record = collect_reconstruction_goal_entries(match, incidents, analyzed_team_id)
            if issue and not source_record.get("trueZeroZero"):
                event_data_issues.append({
                    "id": match.get("id"),
                    "label": make_match_label(match),
                    "competition": get_competition_name(match),
                    "startTimestamp": match.get("startTimestamp") or 0,
                    "type": issue.get("type") or "blocked",
                    "reason": issue.get("reason") or issue.get("message") or "Événements non récupérés",
                    "message": issue.get("message") or "Événements non récupérés pour ce match.",
                })
            if issue and not source_record.get("trueZeroZero"):
                source_record["eventDataStatus"] = issue.get("type") or "blocked"
                source_record["eventDataIssue"] = True
                source_record["error"] = issue.get("reason") or issue.get("message") or "Événements non récupérés"
            elif issue and source_record.get("trueZeroZero"):
                # Un vrai 0-0 n'a aucun but à récupérer: il reste valide même si
                # l'endpoint incidents ne renvoie rien d'exploitable.
                source_record["eventDataStatus"] = "ok-zero-zero"
            elif source_record.get("reconstructionGoalsIncomplete"):
                source_record["eventDataStatus"] = "incomplete-goals"
                source_record["eventDataIssue"] = True
                source_record["error"] = "Buts du match incomplets pour la reconstitution"
                event_data_issues.append({
                    "id": match.get("id"),
                    "label": make_match_label(match),
                    "competition": get_competition_name(match),
                    "startTimestamp": match.get("startTimestamp") or 0,
                    "type": "incomplete-goals",
                    "reason": "Buts du match incomplets pour la reconstitution",
                    "message": "Match ignoré pour la reconstitution: le score indique plus de buts que les incidents récupérés.",
                })
            source_records.append(source_record)

        reconstructed_samples = build_reconstructed_trend_samples(source_records, analyzed_team_id, level_mode=level_mode)
        samples = reconstructed_samples[:needed_matches]

        if len(samples) >= needed_matches:
            break

        known_available = max(0, len(sorted_matches) - skip)
        history_exhausted = bool(stopped_history or next_page >= PAGES_TO_LOAD)
        all_known_sources_processed = total_sources >= known_available
        if history_exhausted and all_known_sources_processed:
            raise RuntimeError(f"{team_name}: pas assez de matchs reconstitués pour {trend_count} tendances ({len(samples)}/{needed_matches}).")

        required += growth_step

    administrative_ignored = sorted(
        administrative_matches_ignored.values(),
        key=lambda item: (item.get("startTimestamp") or 0, item.get("id") or 0),
        reverse=True,
    )

    return {
        "trendMatches": samples,
        "matchesUsed": build_reconstruction_source_matches_used(samples),
        "events": [],
        "eventDataIssues": [],
        "eventDataIssueCount": 0,
        "ignoredSourceIssues": event_data_issues,
        "ignoredSourceIssueCount": len(event_data_issues),
        "administrativeMatchesIgnored": administrative_ignored,
        "administrativeMatchCount": len(administrative_ignored),
        "pagesLoaded": pages_loaded_count,
        "pagesAttempted": pages_attempted_count,
        "pagesLimit": PAGES_TO_LOAD,
        "scanPartial": False,
    }

def build_trend_items(samples, side_key, trend_count, trend_limit_enabled=False):
    items = []
    for i in range(int(trend_count)):
        recent = samples[i]
        previous = samples[i + 1]
        raw_trend_value = (recent.get("level") or 0) - (previous.get("level") or 0)
        trend_value = max(-2.0, min(2.0, float(raw_trend_value))) if trend_limit_enabled else raw_trend_value
        trend_was_limited = bool(trend_limit_enabled and float(raw_trend_value) != float(trend_value))
        previous_minutes = previous.get("minutesForAverage") or [1]
        recent_minutes = recent.get("minutesForAverage") or [1]
        previous_avg_minute = trend_average(previous_minutes)
        recent_avg_minute = trend_average(recent_minutes)
        average_minute_progression = recent_avg_minute - previous_avg_minute
        minutes = recent_minutes + previous_minutes
        avg_minute = trend_average(minutes)
        style = trend_result_style(trend_value)
        items.append({
            "index": i + 1,
            "side": side_key,
            "previousMatch": previous,
            "recentMatch": recent,
            "previousLevel": previous.get("level") or 0,
            "recentLevel": recent.get("level") or 0,
            "value": round(trend_value, 6),
            "rawValue": round(raw_trend_value, 6),
            "performance": round(trend_value, 6),
            "rawPerformance": round(raw_trend_value, 6),
            "trendLimitEnabled": bool(trend_limit_enabled),
            "trendLimited": trend_was_limited,
            "trendLimitMin": -2,
            "trendLimitMax": 2,
            "resultStyle": style,
            "resultLabel": trend_label_from_style(style),
            "averageMinute": round(avg_minute, 4),
            "previousAverageMinute": round(previous_avg_minute, 4),
            "recentAverageMinute": round(recent_avg_minute, 4),
            "averageMinuteProgression": round(average_minute_progression, 4),
            "minuteBasis": [round(float(x), 4) for x in minutes],
            "dominant": False,
            "selectedOldest": False,
            "selectedTrend": False,
            "selectionWeight": 0,
            "selectionTie": False,
            "selectionRank": None,
        })
    return items




def normalize_trend_count(value):
    try:
        n = float(value or 0)
    except Exception:
        n = 0.0
    if not math.isfinite(n):
        n = 0.0
    rounded = round(n, 6)
    if abs(rounded - round(rounded)) < 1e-9:
        return int(round(rounded))
    return rounded


def trend_item_selection_weight(item):
    if not item or not item.get("selectedTrend"):
        return 0.0
    try:
        weight = float(item.get("selectionWeight", item.get("selectedTrendWeight", 1)))
    except Exception:
        weight = 1.0
    if not math.isfinite(weight) or weight <= 0:
        return 0.0
    return weight


def select_trend_items_by_mode(home_items, away_items, selection_mode="top_half", selection_metric="progression", trend_count=None):
    """Sélectionne les tendances sur une zone unique."""
    normalized_mode = str(selection_mode or "top_half").strip().lower()
    if normalized_mode in {"top_line", "line", "topline", "top_ligne", "confrontation", "head_to_head"}:
        normalized_mode = "top_line"
    else:
        normalized_mode = "top_half"

    normalized_metric = str(selection_metric or "progression").strip().lower()
    if normalized_metric in {"global", "global_average", "global_average_minute", "moyenne", "moyenne_globale", "moyenne_minute_globale"}:
        normalized_metric = "global_average_minute"
    else:
        normalized_metric = "progression"

    home_items = home_items or []
    away_items = away_items or []

    try:
        n = int(trend_count or 0)
    except Exception:
        n = 0

    if n <= 0:
        n = max(len(home_items), len(away_items))
    n = max(1, n)

    for items in (home_items, away_items):
        for item in items:
            item["dominant"] = False
            item["selectedTrend"] = False
            item["selectedTrendWeight"] = 0
            item["selectionWeight"] = 0
            item["selectionTie"] = False
            item["selectedOldest"] = False
            item["selectionRank"] = None
            item["selectionMode"] = normalized_mode
            item["selectionMetric"] = normalized_metric
            item["selectionProgression"] = None
            item["selectionDistance"] = None
            item["globalAverageMinute"] = None
            item["timeSourceIndex"] = None
            item["performanceTargetIndex"] = None
            item["timeSourceAverageMinute"] = None
            item["timeSourceProgression"] = None

    combined = []
    all_minutes = []
    side_order = {"home": 0, "away": 1}

    for side_key, items in (("home", home_items), ("away", away_items)):
        for item in items:
            source_index = int(item.get("index") or 0)
            if source_index <= 0 or source_index > n:
                continue

            try:
                progression = float(item.get("averageMinuteProgression"))
            except (TypeError, ValueError):
                recent_avg = trend_average((item.get("recentMatch") or {}).get("minutesForAverage") or [1])
                previous_avg = trend_average((item.get("previousMatch") or {}).get("minutesForAverage") or [1])
                progression = recent_avg - previous_avg
                item["averageMinuteProgression"] = round(progression, 4)
                item["recentAverageMinute"] = round(recent_avg, 4)
                item["previousAverageMinute"] = round(previous_avg, 4)

            minutes = []
            for minute in item.get("minuteBasis") or []:
                try:
                    value = float(minute)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(value):
                    minutes.append(value)
                    all_minutes.append(value)

            average_minute = float(item.get("averageMinute") or (trend_average(minutes) if minutes else 1.0))

            combined.append({
                "side": side_key,
                "item": item,
                "progression": progression,
                "averageMinute": average_minute,
                "sourceIndex": source_index,
                "relativeIndex": source_index,
            })

    total = len(combined)
    global_average = trend_average(all_minutes) if all_minutes else 1.0

    for entry in combined:
        distance = abs(float(entry.get("averageMinute") or 0) - float(global_average))
        entry["distance"] = distance
        entry["item"]["globalAverageMinute"] = round(global_average, 4)
        entry["item"]["selectionDistance"] = round(distance, 4)

    def score_key(entry):
        if normalized_metric == "global_average_minute":
            return (float(entry.get("distance") or 9999), float(entry.get("averageMinute") or 9999))
        return (-float(entry.get("progression") or 0), float(entry.get("averageMinute") or 9999))

    def same_best(a, b):
        if normalized_metric == "global_average_minute":
            return abs(float(a.get("distance") or 9999) - float(b.get("distance") or 9999)) < 1e-9
        return abs(float(a.get("progression") or 0) - float(b.get("progression") or 0)) < 1e-9

    def mark_selected(entry, rank, weight=1.0, tie=False):
        item = entry["item"]
        try:
            clean_weight = float(weight or 0)
        except Exception:
            clean_weight = 0.0
        if not math.isfinite(clean_weight) or clean_weight <= 0:
            clean_weight = 0.0
        item["dominant"] = clean_weight > 0
        item["selectedTrend"] = clean_weight > 0
        item["selectedOldest"] = clean_weight > 0
        item["selectionWeight"] = round(clean_weight, 6)
        item["selectedTrendWeight"] = round(clean_weight, 6)
        item["selectionTie"] = bool(tie)
        item["selectionRank"] = rank
        item["selectionMode"] = normalized_mode
        item["selectionMetric"] = normalized_metric
        item["selectionProgression"] = round(float(entry.get("progression") or 0), 4)
        item["selectionDistance"] = round(float(entry.get("distance") or 0), 4)
        item["globalAverageMinute"] = round(global_average, 4)

    selected = []
    label = "Top Moitié" if normalized_mode == "top_half" else "Top Ligne"

    if total <= 0:
        return {
            "method": normalized_mode,
            "label": label,
            "selectionMetric": normalized_metric,
            "selectionMetricLabel": "Moyenne Minute Globale" if normalized_metric == "global_average_minute" else "Progression Moyenne",
            "requestedTrendCount": n,
            "calculationTrendCount": n,
            "totalTrendItems": 0,
            "selectedTrendItems": 0,
            "globalAverageMinute": round(global_average, 4),
            "cutoffProgression": None,
            "cutoffDistance": None,
            "homeSelectedTrendItems": 0,
            "awaySelectedTrendItems": 0,
        }

    if normalized_mode == "top_line":
        by_relative = {}
        for entry in combined:
            by_relative.setdefault(entry["relativeIndex"], []).append(entry)

        rank = 1
        for relative_index in sorted(by_relative.keys()):
            candidates = sorted(
                by_relative[relative_index],
                key=lambda entry: (*score_key(entry), side_order.get(entry["side"], 9)),
            )
            if not candidates:
                continue

            best = candidates[0]
            winners = [entry for entry in candidates if same_best(entry, best)]

            tie = len(winners) > 1
            weight = 1.0 / len(winners) if winners else 1.0
            for entry in winners:
                mark_selected(entry, rank, weight=weight, tie=tie)
                selected.append(entry)
            rank += 1

    else:
        selected_count = max(1, (total + 1) // 2)
        ordered = sorted(
            combined,
            key=lambda entry: (*score_key(entry), entry["relativeIndex"], side_order.get(entry["side"], 9)),
        )
        selected = ordered[:selected_count]

        for rank, entry in enumerate(selected, start=1):
            mark_selected(entry, rank)

    cutoff_progression = min((float(entry.get("progression") or 0) for entry in selected), default=None)
    cutoff_distance = max((float(entry.get("distance") or 0) for entry in selected), default=None)

    home_selected_weight = sum(trend_item_selection_weight(item) for item in home_items or [])
    away_selected_weight = sum(trend_item_selection_weight(item) for item in away_items or [])

    return {
        "method": normalized_mode,
        "label": label,
        "selectionMetric": normalized_metric,
        "selectionMetricLabel": "Moyenne Minute Globale" if normalized_metric == "global_average_minute" else "Progression Moyenne",
        "requestedTrendCount": n,
        "calculationTrendCount": n,
        "totalTrendItems": total,
        "selectedTrendItems": normalize_trend_count(home_selected_weight + away_selected_weight),
        "globalAverageMinute": round(global_average, 4),
        "cutoffProgression": round(cutoff_progression, 4) if cutoff_progression is not None else None,
        "cutoffDistance": round(cutoff_distance, 4) if cutoff_distance is not None else None,
        "homeSelectedTrendItems": normalize_trend_count(home_selected_weight),
        "awaySelectedTrendItems": normalize_trend_count(away_selected_weight),
    }


def summarize_trend_items(items):
    counts = {"V": 0.0, "N": 0.0, "D": 0.0}
    performance_score = 0.0
    dominant_count = 0.0

    for item in items or []:
        weight = trend_item_selection_weight(item)
        if weight <= 0:
            continue
        dominant_count += weight
        value = float(item.get("value") or 0)
        performance_score += value * weight
        style = trend_result_style(value)
        counts[style] = counts.get(style, 0.0) + weight

    normalized_counts = {key: normalize_trend_count(value) for key, value in counts.items()}
    order = sorted(
        [{"style": k, "label": trend_label_from_style(k), "count": v} for k, v in normalized_counts.items()],
        key=lambda item: (-float(item["count"] or 0), {"V": 0, "N": 1, "D": 2}.get(item["style"], 9)),
    )
    primary = order[0] if order and float(order[0]["count"] or 0) > 0 else None
    secondary = order[1] if len(order) > 1 and float(order[1]["count"] or 0) > 0 else None

    return {
        "performanceScore": round(performance_score, 6),
        "resultCounts": normalized_counts,
        "primaryResult": primary,
        "secondaryResult": secondary,
        "dominantCount": normalize_trend_count(dominant_count),
    }

def process_trend_scan_job(job_id, params):
    match_id = str(params.get("matchId") or "").strip()
    trend_count = int(float(params.get("trendCount") or params.get("rank1") or 4))
    trend_count = max(1, min(100, trend_count))
    skip_home = int(params.get("skipHome") or 0)
    skip_away = int(params.get("skipAway") or 0)
    simultaneous_mode = truthy_param(params.get("simultaneousMode"))
    trend_limit_enabled = truthy_param(params.get("trendLimitEnabled"))
    trend_selection_mode = str(params.get("trendSelectionMode") or "top_line").strip()
    if trend_selection_mode not in {"top_line", "top_half"}:
        trend_selection_mode = "top_line"
    trend_selection_metric = str(params.get("trendSelectionMetric") or "global_average_minute").strip()
    if trend_selection_metric not in {"progression", "global_average_minute"}:
        trend_selection_metric = "global_average_minute"

    calculation_trend_count = trend_count

    update_scan_job(job_id, status="running", message="Récupération Du Match Principal…", progress=5)
    match_data = get_json(f"event/{match_id}")
    match = match_data.get("event") if isinstance(match_data, dict) else match_data

    if not isinstance(match, dict) or not match.get("homeTeam") or not match.get("awayTeam"):
        raise RuntimeError("Format du match principal inattendu")

    home_team = match["homeTeam"]
    away_team = match["awayTeam"]
    needed_matches = calculation_trend_count + 1

    update_scan_job(
        job_id,
        status="running",
        message=f"Match trouvé : {home_team.get('name')} vs {away_team.get('name')} · {trend_count} tendances ({needed_matches} matchs)",
        progress=10,
    )

    level_mode = "full" if simultaneous_mode else "attack"

    home_scan = fetch_trend_team_matches(job_id, home_team["id"], skip_home, calculation_trend_count, home_team.get("name") or "Domicile", 12, 40, level_mode=level_mode)
    away_scan = fetch_trend_team_matches(job_id, away_team["id"], skip_away, calculation_trend_count, away_team.get("name") or "Extérieur", 54, 40, level_mode=level_mode)

    if not simultaneous_mode:
        # Séparé = offensif vs offensif aligné par ligne :
        # A ligne N = attaque A ligne N + attaque de l'adversaire passé de B ligne N.
        # B ligne N = attaque B ligne N + attaque de l'adversaire passé de A ligne N.
        home_combined = build_separated_offensive_samples(home_scan["trendMatches"], away_scan["trendMatches"], "home")
        away_combined = build_separated_offensive_samples(away_scan["trendMatches"], home_scan["trendMatches"], "away")
        home_scan["trendMatchesDirect"] = home_scan["trendMatches"]
        away_scan["trendMatchesDirect"] = away_scan["trendMatches"]
        home_scan["trendMatches"] = home_combined
        away_scan["trendMatches"] = away_combined
        home_scan["matchesUsed"] = rebuild_trend_matches_used_from_samples(home_combined)
        away_scan["matchesUsed"] = rebuild_trend_matches_used_from_samples(away_combined)

    home_items = build_trend_items(home_scan["trendMatches"], "home", calculation_trend_count, trend_limit_enabled=trend_limit_enabled)
    away_items = build_trend_items(away_scan["trendMatches"], "away", calculation_trend_count, trend_limit_enabled=trend_limit_enabled)

    # Zone unique : la sélection et la performance utilisent les mêmes tendances.
    trend_selection = select_trend_items_by_mode(
        home_items,
        away_items,
        trend_selection_mode,
        trend_selection_metric,
        trend_count=trend_count,
    )
    comparisons = []

    for i in range(calculation_trend_count):
        home_item = home_items[i]
        away_item = away_items[i]
        hm = float(home_item.get("averageMinute") or 0)
        am = float(away_item.get("averageMinute") or 0)
        home_selected = bool(home_item.get("selectedTrend"))
        away_selected = bool(away_item.get("selectedTrend"))

        if home_selected and away_selected:
            dominant = "both"
        elif home_selected:
            dominant = "home"
        elif away_selected:
            dominant = "away"
        else:
            dominant = "none"

        comparisons.append({
            "index": i + 1,
            "dominant": dominant,
            "home": home_item,
            "away": away_item,
            "minuteDiff": round(abs(hm - am), 4),
        })

    home_summary = summarize_trend_items(home_items)
    away_summary = summarize_trend_items(away_items)

    def winner():
        h = home_summary["performanceScore"]
        a = away_summary["performanceScore"]

        if h == a:
            return {"type": "tie", "side": "tie", "label": "Égalité", "score": h, "diff": 0}

        normal_side = "home" if h > a else "away"
        home_taken_trends = float(trend_selection.get("homeSelectedTrendItems") or 0)
        away_taken_trends = float(trend_selection.get("awaySelectedTrendItems") or 0)
        zero_side = "home" if h == 0 else ("away" if a == 0 else None)
        more_taken_side = None
        if home_taken_trends > away_taken_trends:
            more_taken_side = "home"
        elif away_taken_trends > home_taken_trends:
            more_taken_side = "away"
        switched = bool(zero_side and zero_side == more_taken_side)
        side = ("away" if normal_side == "home" else "home") if switched else normal_side

        if side == "home":
            result_winner = {"type": "winner", "side": "home", "label": home_team.get("name"), "score": h, "diff": round(abs(h - a), 6)}
        else:
            result_winner = {"type": "winner", "side": "away", "label": away_team.get("name"), "score": a, "diff": round(abs(h - a), 6)}

        if switched:
            result_winner.update({
                "switch": True,
                "switchReason": "zero_performance",
                "originalWinnerSide": normal_side,
                "originalWinnerLabel": home_team.get("name") if normal_side == "home" else away_team.get("name"),
                "originalWinnerScore": h if normal_side == "home" else a,
            })

        return result_winner

    home_issue_count = int(home_scan.get("eventDataIssueCount") or 0)
    away_issue_count = int(away_scan.get("eventDataIssueCount") or 0)
    total_issue_count = home_issue_count + away_issue_count
    home_ignored_issue_count = int(home_scan.get("ignoredSourceIssueCount") or 0)
    away_ignored_issue_count = int(away_scan.get("ignoredSourceIssueCount") or 0)
    total_ignored_issue_count = home_ignored_issue_count + away_ignored_issue_count
    home_admin_count = int(home_scan.get("administrativeMatchCount") or 0)
    away_admin_count = int(away_scan.get("administrativeMatchCount") or 0)
    total_admin_count = home_admin_count + away_admin_count

    result = {
        "trendMode": True,
        "trendCount": trend_count,
        "trendCalculationCount": calculation_trend_count,
        "trendMatchesNeeded": needed_matches,
        "simultaneousMode": simultaneous_mode,
        "scanModeLabel": "Camp Séparé" if simultaneous_mode else "Camp Combiné",
        "trendLevelMode": level_mode,
        "trendLimitEnabled": trend_limit_enabled,
        "trendLimitRange": [-2, 2] if trend_limit_enabled else None,
        "trendSelectionMode": trend_selection_mode,
        "trendSelectionMetric": trend_selection_metric,
        "trendSelection": trend_selection,
        "match": {
            "id": match.get("id"),
            "homeTeam": home_team,
            "awayTeam": away_team,
            "startTimestamp": match.get("startTimestamp"),
            "label": make_match_label(match),
        },
        "home": {
            **home_team,
            **home_scan,
            "trend": {**home_summary, "items": home_items},
            "r1": {"value": home_summary["performanceScore"], "sources": []},
            "r2": None,
            "zoneStats": {"average": None, "count": 0},
        },
        "away": {
            **away_team,
            **away_scan,
            "trend": {**away_summary, "items": away_items},
            "r1": {"value": away_summary["performanceScore"], "sources": []},
            "r2": None,
            "zoneStats": {"average": None, "count": 0},
        },
        "trendComparisons": comparisons,
        "trendWinner": winner(),
        "requestedRank1": trend_count,
        "requestedRank2": None,
        "rank1": trend_count,
        "rank2": None,
        "dataQuality": {
            "isPartial": total_issue_count > 0,
            "eventDataIssueCount": total_issue_count,
            "homeIssueCount": home_issue_count,
            "awayIssueCount": away_issue_count,
            "administrativeMatchCount": total_admin_count,
            "homeAdministrativeMatchCount": home_admin_count,
            "awayAdministrativeMatchCount": away_admin_count,
            "administrativeMatchesIgnored": (home_scan.get("administrativeMatchesIgnored") or []) + (away_scan.get("administrativeMatchesIgnored") or []),
            "ignoredSourceIssueCount": total_ignored_issue_count,
            "homeIgnoredSourceIssueCount": home_ignored_issue_count,
            "awayIgnoredSourceIssueCount": away_ignored_issue_count,
            "ignoredSourceIssues": (home_scan.get("ignoredSourceIssues") or []) + (away_scan.get("ignoredSourceIssues") or []),
            "message": (
                f"⚠️ Scan partiel : {total_issue_count} match(s) utilisé(s) sans événements récupérés."
                if total_issue_count else
                "Scan complet : reconstitutions valides. Les matchs incomplets éventuels ont été ignorés et remplacés."
            ),
        },
        "config": {
            "trendCount": trend_count,
            "trendMatchesNeeded": needed_matches,
            "pagesToLoad": PAGES_TO_LOAD,
            "system": "trend",
            "trendLevelMode": level_mode,
            "trendLimitEnabled": trend_limit_enabled,
            "trendLimitRange": [-2, 2] if trend_limit_enabled else None,
            "trendSelectionMode": trend_selection_mode,
            "trendSelectionMetric": trend_selection_metric,
                "trendCalculationCount": calculation_trend_count,
            "trendSelectionMethod": trend_selection.get("method"),
            "trendSelection": trend_selection,
        },
    }

    update_scan_job(job_id, status="done", message="📈 Scan tendance terminé.", progress=100, result=result, finishedAt=now_ts())
    print(f"✅ Scan tendance terminé: {job_id} · {trend_count} tendances · gagnant {result['trendWinner']['label']}")

def process_scan_job(job_id):
    raw = redis_cmd("GET", f"{SCAN_JOB_PREFIX}{job_id}")

    if not raw:
        print(f"Scan job absent: {job_id}")
        return

    job = json.loads(raw)
    params = job.get("params") or {}

    if params.get("trendMode") or params.get("trendCount") is not None:
        try:
            process_trend_scan_job(job_id, params)
        except Exception as e:
            update_scan_job(job_id, status="error", message="Erreur pendant le scan tendance.", progress=100, error=str(e))
            print(f"ERREUR scan tendance {job_id}: {e}", file=sys.stderr)
        return

    match_id = str(params.get("matchId") or "").strip()
    rank1 = float(params.get("rank1"))
    rank2 = params.get("rank2")
    rank2 = float(rank2) if rank2 is not None else None
    skip_home = int(params.get("skipHome") or 0)
    skip_away = int(params.get("skipAway") or 0)
    simultaneous_mode = bool(params.get("simultaneousMode"))
    rank_event_step = params.get("rankEventStep", DEFAULT_RANK_EVENT_STEP)
    rank_event_mode = params.get("rankEventMode") or params.get("rankStepMode") or "fixed"
    winner_mode = "evolution" if params.get("winnerMode") == "evolution" else "dominance"
    configure_rank_advancement(rank_event_step, rank_event_mode)

    effective_rank1 = rank1
    effective_rank2 = rank2

    ranks = [effective_rank1]

    if effective_rank2 is not None:
        ranks.append(effective_rank2)

    max_needed = float(max(ranks))

    # En mode simultané, on ne doit pas arrêter le scan sur le total brut
    # équipe + adversaires. Chaque équipe doit d'abord avoir assez de progression
    # directe pour atteindre le rang demandé. Les événements des adversaires passés
    # restent un complément pondéré dans le flux final.
    scan_fetch_needed = max_needed

    print(
        f"🔎 Scan complet: job={job_id} match={match_id} "
        f"ranks demandés={[rank1, rank2]} ranks utilisés={ranks} "
        f"objectif progression={scan_fetch_needed} simultaneous={simultaneous_mode} "
        f"progression={rank_advancement_label()}"
    )

    try:
        update_scan_job(job_id, status="running", message="Récupération Du Match Principal…", progress=5)

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
            direct_team_only=not simultaneous_mode,
            completion_mode="team_direct" if simultaneous_mode else "total",
        )

        away_scan = scan_team(
            job_id,
            away_team["id"],
            skip_away,
            scan_fetch_needed,
            away_team.get("name") or "Extérieur",
            54,
            40,
            direct_team_only=not simultaneous_mode,
            completion_mode="team_direct" if simultaneous_mode else "total",
        )

        simultaneous_combined_events = []

        if simultaneous_mode:
            update_scan_job(
                job_id,
                status="running",
                message="Calcul simultané: équipe + adversaires passés opposés, match/minute…",
                progress=96,
            )
            home_scan, away_scan, simultaneous_combined_events = apply_simultaneous_match_minute_order(
                home_scan,
                away_scan,
                home_team.get("name") or "Domicile",
                away_team.get("name") or "Extérieur",
            )

            # Affichage déterministe en mode simultané: ne jamais montrer la marge
            # récupérée en réserve. Le diviseur ADV est propre à chaque calcul cible :
            # rangs A => matchs B utilisés pour A ; rangs B => matchs A utilisés pour B.
            home_scan = finalize_simultaneous_scan_to_used(home_scan, max_needed)
            away_scan = finalize_simultaneous_scan_to_used(away_scan, max_needed)
            simultaneous_combined_events = rebuild_simultaneous_combined_events(home_scan, away_scan)
            simultaneous_combined_events = trim_events_to_rank_need(simultaneous_combined_events, max_needed * 2)

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

        home_issue_count = int(home.get("eventDataIssueCount") or 0)
        away_issue_count = int(away.get("eventDataIssueCount") or 0)
        total_issue_count = home_issue_count + away_issue_count
        home_admin_count = int(home.get("administrativeMatchCount") or 0)
        away_admin_count = int(away.get("administrativeMatchCount") or 0)
        total_admin_count = home_admin_count + away_admin_count
        data_quality = {
            "isPartial": total_issue_count > 0,
            "eventDataIssueCount": total_issue_count,
            "homeIssueCount": home_issue_count,
            "awayIssueCount": away_issue_count,
            "administrativeMatchCount": total_admin_count,
            "homeAdministrativeMatchCount": home_admin_count,
            "awayAdministrativeMatchCount": away_admin_count,
            "administrativeMatchesIgnored": (home.get("administrativeMatchesIgnored") or []) + (away.get("administrativeMatchesIgnored") or []),
            "message": (
                f"⚠️ Scan partiel : {total_issue_count} match(s) sans événements récupérés. "
                "Les buts de ces matchs ne sont pas comptés."
                if total_issue_count else
                "Scan complet : aucun match sans événements récupérés."
            ),
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
            "rankEventStep": CURRENT_RANK_EVENT_STEP,
            "rankEventMode": CURRENT_RANK_ADVANCEMENT_MODE,
            "rankEventStepLabel": rank_advancement_label(),
            "winnerMode": winner_mode,
            "scanModeLabel": "Simultané: équipe + adversaires passés opposés, match par match / minute" if simultaneous_mode else "Séparé: équipe + adversaires passés pondérés",
            "overallZoneStats": None,
            "dataQuality": data_quality,
            "config": {
                "pagesToLoad": PAGES_TO_LOAD,
                "initialMatchesPerTeam": INITIAL_MATCHES_PER_TEAM,
                "secondMatchesPerTeam": SECOND_MATCHES_PER_TEAM,
                "maxMatchesPerTeam": MAX_MATCHES_PER_TEAM,
                "incidentBatchSize": INCIDENT_BATCH_SIZE,
                "zoneMethod": "final_ranks_low_to_high",
                "rankEventStep": CURRENT_RANK_EVENT_STEP,
                "rankEventMode": CURRENT_RANK_ADVANCEMENT_MODE,
                "rankEventStepLabel": rank_advancement_label(),
                "winnerMode": winner_mode,
            },
        }

        update_scan_job(
            job_id,
            status="done",
            message="🔎 Scan terminé.",
            progress=100,
            result=result,
            finishedAt=now_ts(),
        )

        if data_quality["isPartial"]:
            print(f"⚠️ Scan terminé avec données partielles: {job_id} · {data_quality['eventDataIssueCount']} match(s) sans événements récupérés")
        else:
            print(f"✅ Scan terminé complet: {job_id} · aucun événement ignoré")
        if data_quality.get("administrativeMatchCount"):
            print(f"🚫 Matchs forfait/administratifs ignorés: {data_quality['administrativeMatchCount']}")

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
    print("Version niveau 1: 🔎 scan complet côté worker activé.")
    print("Pages Web: 10 Pages d’abord, extension automatique à 15 puis 20 si nécessaire.")
    print("Mode séparé: équipe analysée + adversaires passés pondérés par match utilisé.")
    print("Mode simultané: équipe + adversaires passés opposés, match par match, minute par minute.")
    print("Option B: scan progressif 15 → 17 → 20 matchs activé.")
    print("Système tendance: curseur 1-100, comparaison par moyenne des minutes la plus basse.")
    print("Événements: buts uniquement (But Avec Passeur, But Sans Passeur, CSC / Erreur). Cartons et passes seules ignorés.")
    print("Stabilité réseau: retry Web + matchs sans événements SofaScore signalés clairement.")
    print("Préchargement événements: désactivé par défaut pour économiser les requêtes.")
    print("Laisse cette fenêtre ouverte pendant que tu utilises l'app.")

    while True:
        try:
            # BRPOP évite le polling agressif (anciennement 3 requêtes Redis
            # toutes les 0,5 s même sans scan). Une seule requête attend
            # jusqu'à 10 s qu'un job arrive, ce qui protège le quota Upstash.
            result = redis_cmd(
                "BRPOP",
                SCAN_QUEUE_KEY,
                RAW_QUEUE_KEY,
                RAW_PREFETCH_QUEUE_KEY,
                "1" if once else "10",
            )
        except RuntimeError as e:
            if is_upstash_quota_error(e):
                print("\n❌ Quota Upstash atteint: limite de requêtes dépassée.")
                print("Le worker ne peut plus lire la file tant que le quota n'est pas réinitialisé ou augmenté.")
                print("Solution: attendre le reset Upstash, passer l'instance en plan supérieur, ou changer de base Redis.")
                print("Note: le polling du worker a été optimisé pour éviter de consommer le quota à vide.")
                break
            raise

        queue_key, value = parse_brpop_result(result)

        if not value:
            if once:
                print("Aucune requête en attente.")
                break
            continue

        if queue_key == SCAN_QUEUE_KEY:
            process_scan_job(value)
            continue

        if queue_key == RAW_QUEUE_KEY:
            process_raw_request(value)
            continue

        if queue_key == RAW_PREFETCH_QUEUE_KEY:
            process_prefetch_path(value)
            continue

        # Sécurité: si le provider renvoie un format inattendu, on priorise
        # l'ancien flux scan pour ne pas perdre le job.
        process_scan_job(value)


if __name__ == "__main__":
    main()
