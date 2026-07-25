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
SCAN_PENDING_SET_KEY = "footscan:scan:pending"
SCAN_LATEST_KEY = "footscan:scan:latest"
SCAN_WORKER_HEARTBEAT_KEY = "footscan:worker:heartbeat"
SCAN_WAKE_QUEUE_KEY = os.environ.get("SCAN_WAKE_QUEUE", "sofa:queue")

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
RECONSTRUCTION_WINDOW_BASE_MATCHES = max(10, int(os.environ.get("FOOTSCAN_RECONSTRUCTION_WINDOW_BASE", "30")))
RECONSTRUCTION_WINDOW_MAX_MATCHES = max(RECONSTRUCTION_WINDOW_BASE_MATCHES, int(os.environ.get("FOOTSCAN_RECONSTRUCTION_WINDOW_MAX", "40")))
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


def normalize_queue_key(value):
    text = str(value or "").strip()
    if (text.startswith("b'") and text.endswith("'")) or (text.startswith('b"') and text.endswith('"')):
        text = text[2:-1]
    return text.strip("'\"")


def parse_brpop_result(result):
    """Retourne (queue_key, value) pour BRPOP, ou (None, None).

    Upstash renvoie normalement [key, value]. On reste tolérant
    si le format varie légèrement.
    """
    if not result:
        return None, None
    if isinstance(result, (list, tuple)) and len(result) >= 2:
        return normalize_queue_key(result[0]), result[1]
    return None, result


def looks_like_scan_job_id(value):
    text = str(value or "").strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]{24}", text))


LAST_HEARTBEAT_SENT_AT = 0
LAST_IDLE_LOG_AT = 0


def send_worker_heartbeat(force=False):
    global LAST_HEARTBEAT_SENT_AT
    ts = now_ts()
    if not force and ts - LAST_HEARTBEAT_SENT_AT < 15:
        return
    payload = {
        "status": "online",
        "ts": ts,
        "version": "v209",
        "queue": SCAN_QUEUE_KEY,
        "pendingSet": SCAN_PENDING_SET_KEY,
    }
    redis_cmd("SET", SCAN_WORKER_HEARTBEAT_KEY, json.dumps(payload, ensure_ascii=False), "EX", "120")
    LAST_HEARTBEAT_SENT_AT = ts


def pop_latest_scan_job():
    value = redis_cmd("GET", SCAN_LATEST_KEY)
    if not value or not looks_like_scan_job_id(value):
        return None

    raw = redis_cmd("GET", f"{SCAN_JOB_PREFIX}{value}")
    if not raw:
        redis_cmd("DEL", SCAN_LATEST_KEY)
        return None

    try:
        job = json.loads(raw)
    except Exception:
        redis_cmd("DEL", SCAN_LATEST_KEY)
        return None

    status = str(job.get("status") or "").lower()
    if status in {"queued", "pending"}:
        redis_cmd("DEL", SCAN_LATEST_KEY)
        return value

    # Évite une boucle infinie sur un ancien latest déjà traité.
    redis_cmd("DEL", SCAN_LATEST_KEY)
    return None


def pop_scan_job_fallback():
    """Lecture scan robuste.

    v209 ne dépend plus d'un seul mécanisme Redis. Le worker vérifie:
    1) le set pending, 2) la file dans les deux sens, 3) la clé latest de secours.
    """
    value = redis_cmd("SPOP", SCAN_PENDING_SET_KEY)
    if value:
        return value

    value = redis_cmd("RPOP", SCAN_QUEUE_KEY)
    if value:
        return value

    value = redis_cmd("LPOP", SCAN_QUEUE_KEY)
    if value:
        return value

    return pop_latest_scan_job()


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

EXTRA_TIME_PENALTY_KEYWORDS = (
    "after extra time", "extra time", "aet", "a.e.t",
    "overtime", "prolongation", "prolongations",
    "apres prolongation", "apres prolongations",
    "after penalties", "penalties", "penalty shootout",
    "penalty shoot-out", "penalty kicks", "shootout",
    "tirs au but", "tir au but", "apres tirs au but",
    "tab",
)

EXTRA_TIME_PENALTY_SCORE_KEYS = (
    "extra", "overtime", "penalt", "shootout", "period3", "period4",
)


def score_pair_for_key(match, key):
    home = match.get("homeScore") or {}
    away = match.get("awayScore") or {}
    if not isinstance(home, dict) or not isinstance(away, dict):
        return None, None
    return safe_score_value(home.get(key)), safe_score_value(away.get(key))


def extra_time_or_penalty_match_reason(match):
    """Détecte les matchs à prolongation ou tirs au but à exclure.

    FOOTSCAN doit analyser uniquement le temps réglementaire normal. Un match
    qui va en prolongation ou aux tirs au but est donc ignoré/remplacé au lieu
    de mélanger des scores issus d'une configuration différente.
    """
    if not isinstance(match, dict):
        return None

    values = []

    def add(value):
        if value is None:
            return
        if isinstance(value, (str, int, float, bool)):
            text = str(value).strip()
            if text:
                values.append(text)

    status = match.get("status") or {}
    if isinstance(status, dict):
        for key in ("type", "description", "reason", "text", "name", "short", "detail"):
            add(status.get(key))

    for key in (
        "statusDescription", "statusText", "statusReason", "reason",
        "note", "notes", "description", "resultType", "matchStatus",
        "winnerCode", "period", "phase", "resultDescription",
    ):
        add(match.get(key))

    haystack = " | ".join(normalize_status_text(v) for v in values if str(v).strip())
    for keyword in EXTRA_TIME_PENALTY_KEYWORDS:
        if keyword in haystack:
            return f"Prolongation/tirs au but détectés: {keyword}"

    for key in (
        "hasExtraTime", "extraTime", "afterExtraTime", "overtime",
        "hasPenalties", "penalties", "penaltyShootout",
        "hasPenaltyShootout", "decidedByPenalties", "shootout",
    ):
        if match.get(key) is True:
            return f"Prolongation/tirs au but détectés: {key}"

    home_score = match.get("homeScore") or {}
    away_score = match.get("awayScore") or {}
    for score in (home_score, away_score):
        if not isinstance(score, dict):
            continue
        for key, value in score.items():
            normalized_key = normalize_status_text(key)
            if any(fragment in normalized_key for fragment in EXTRA_TIME_PENALTY_SCORE_KEYS):
                numeric = safe_score_value(value)
                if numeric is not None and numeric != 0:
                    return f"Prolongation/tirs au but détectés: score {key}"

    # Sur SofaScore, normaltime/current différents signale souvent un résultat
    # modifié après prolongation ou tirs au but. On l'exclut prudemment.
    for baseline_key in ("normaltime", "regularTime"):
        current_home, current_away = score_pair_for_key(match, "current")
        base_home, base_away = score_pair_for_key(match, baseline_key)
        if current_home is not None and current_away is not None and base_home is not None and base_away is not None:
            if current_home != base_home or current_away != base_away:
                return "Prolongation/tirs au but détectés: score final différent du temps réglementaire"

    return None


def incidents_indicate_extra_time_or_penalty(incidents):
    for incident in incidents or []:
        if not isinstance(incident, dict):
            continue

        incident_type = normalize_status_text(incident.get("incidentType"))
        incident_class = normalize_status_text(incident.get("incidentClass"))
        reason = normalize_status_text(incident.get("reason") or incident.get("description") or incident.get("text"))
        haystack = " | ".join([incident_type, incident_class, reason])
        if any(keyword in haystack for keyword in EXTRA_TIME_PENALTY_KEYWORDS):
            return True

        try:
            if incident_phase_rank(incident) > 1:
                return True
        except Exception:
            minute = incident.get("time")
            try:
                if minute is not None and float(minute) > 90:
                    return True
            except Exception:
                pass

    return False


def administrative_match_reason(match, include_extra=False):
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

    extra_reason = extra_time_or_penalty_match_reason(match)
    if extra_reason and not include_extra:
        return extra_reason

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
    reason_text = reason or "Match administratif / forfait"
    normalized_reason = normalize_status_text(reason_text)
    if "prolongation" in normalized_reason or "penalt" in normalized_reason or "tir" in normalized_reason or "shootout" in normalized_reason:
        issue_type = "extra-time-penalties"
        message = "Match ignoré: prolongation ou tirs au but exclus de l'analyse."
    else:
        issue_type = "administrative"
        message = "Match ignoré: forfait, abandon, report, annulation ou décision administrative."
    return {
        "id": match.get("id"),
        "label": make_match_label(match),
        "competition": get_competition_name(match),
        "startTimestamp": match.get("startTimestamp") or 0,
        "type": issue_type,
        "reason": reason_text,
        "message": message,
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


def scan_team(job_id, analyzed_team_id, skip, max_needed, team_name, base_progress, progress_span, direct_team_only=False, completion_mode="total", include_extra=False):
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

            admin_reason = administrative_match_reason(match, include_extra=include_extra)
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

                    if incidents_indicate_extra_time_or_penalty(incidents):
                        issue = {
                            "id": match.get("id"),
                            "label": make_match_label(match),
                            "competition": get_competition_name(match),
                            "startTimestamp": match.get("startTimestamp") or 0,
                            "type": "extra-time-penalties",
                            "reason": "Prolongation ou tirs au but détectés dans les événements",
                            "message": "Match ignoré: prolongation ou tirs au but exclus de l'analyse.",
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
                                "eventDataStatus": "extra-time-penalties",
                                "eventDataIssue": True,
                                "error": "Prolongation ou tirs au but exclus de l'analyse",
                            },
                        })
                        continue

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


def invert_trend_result_style(style):
    """Variance finale du résultat: V devient D, D devient V, N reste N."""
    key = str(style or "").strip().upper()[:1]
    if key == "V":
        return "D"
    if key == "D":
        return "V"
    if key == "N":
        return "N"
    return "N"


def build_result_profile(counts, apply_variance=True):
    """Construit le résultat principal sans résultat secondaire arbitraire.

    Si plusieurs résultats ont le même meilleur total, ils sont tous renvoyés
    dans primaryResults. secondaryResult reste volontairement nul pour éviter
    l'ancien affichage entre parenthèses.
    """
    base_counts = {"V": 0.0, "N": 0.0, "D": 0.0}
    for key, value in (counts or {}).items():
        style = str(key or "").strip().upper()[:1]
        if style not in base_counts:
            continue
        try:
            amount = float(value or 0)
        except Exception:
            amount = 0.0
        if math.isfinite(amount):
            base_counts[style] += amount

    final_counts = {"V": 0.0, "N": 0.0, "D": 0.0}
    for style, value in base_counts.items():
        target = invert_trend_result_style(style) if apply_variance else style
        final_counts[target] += value

    normalized_raw_counts = {key: normalize_trend_count(value) for key, value in base_counts.items()}
    normalized_counts = {key: normalize_trend_count(value) for key, value in final_counts.items()}

    result_order = {"V": 0, "N": 1, "D": 2}
    ordered = sorted(
        [{"style": k, "label": trend_label_from_style(k), "count": v} for k, v in normalized_counts.items()],
        key=lambda item: (-float(item["count"] or 0), result_order.get(item["style"], 9)),
    )
    top_count = float(ordered[0]["count"] or 0) if ordered else 0.0
    primary_results = [item for item in ordered if top_count > 0 and abs(float(item["count"] or 0) - top_count) < 1e-9]
    primary = primary_results[0] if primary_results else None
    result_text = "/".join(item["style"] for item in primary_results) if primary_results else "—"

    # Score de départage déterministe quand les performances finales sont égales.
    # V compte positif, D négatif, N neutre.
    result_decision_score = float(final_counts.get("V") or 0) - float(final_counts.get("D") or 0)
    result_decision_vector = [
        result_decision_score,
        float(final_counts.get("V") or 0),
        float(final_counts.get("N") or 0),
        -float(final_counts.get("D") or 0),
    ]

    return {
        "rawResultCounts": normalized_raw_counts,
        "resultCounts": normalized_counts,
        "primaryResult": primary,
        "primaryResults": primary_results,
        "secondaryResult": None,
        "resultText": result_text,
        "resultDecisionScore": round(result_decision_score, 6),
        "resultDecisionVector": [round(value, 6) for value in result_decision_vector],
        "resultVarianceApplied": bool(apply_variance),
    }


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


def match_score_pair(match, regulation_time_limit=True):
    """Retourne le score final fiable du match source quand il existe.

    Si la limitation du temps réglementaire est active, on privilégie le score
    de temps réglementaire. Sinon, on privilégie le score final courant pour
    permettre les prolongations/tirs au but quand Avec Extra est activé.
    """
    home_score = match.get("homeScore") or {}
    away_score = match.get("awayScore") or {}

    keys = ("normaltime", "regularTime", "current", "display") if regulation_time_limit else ("current", "display", "normaltime", "regularTime")
    for key in keys:
        home = safe_score_value(home_score.get(key))
        away = safe_score_value(away_score.get(key))
        if home is not None and away is not None:
            return home, away

    return None, None


def match_score_total(match, regulation_time_limit=True):
    home, away = match_score_pair(match, regulation_time_limit=regulation_time_limit)
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


def reconstruction_score_average(values):
    clean = []
    for value in values or []:
        try:
            n = float(value)
        except Exception:
            continue
        if math.isfinite(n):
            clean.append(n)
    return sum(clean) / len(clean) if clean else 0.0


def reconstruction_number_label(value):
    try:
        n = float(value)
    except Exception:
        n = 0.0
    if not math.isfinite(n):
        n = 0.0
    if abs(n - round(n)) < 1e-9:
        return str(int(round(n)))
    return f"{n:.2f}".rstrip("0").rstrip(".")


def incident_score_pair(incident):
    """Lit le score exposé par SofaScore au moment du but quand il existe."""
    if not isinstance(incident, dict):
        return None, None

    direct_pairs = [
        ("homeScore", "awayScore"),
        ("home_score", "away_score"),
    ]
    for home_key, away_key in direct_pairs:
        home = incident.get(home_key)
        away = incident.get(away_key)
        if isinstance(home, dict):
            for key in ("current", "display", "normaltime", "value"):
                h = safe_score_value(home.get(key))
                a = safe_score_value(away.get(key) if isinstance(away, dict) else away)
                if h is not None and a is not None:
                    return h, a
        else:
            h = safe_score_value(home)
            a = safe_score_value(away)
            if h is not None and a is not None:
                return h, a

    score = incident.get("score") or incident.get("incidentScore") or incident.get("currentScore")
    if isinstance(score, dict):
        home = None
        away = None
        for key in ("home", "homeScore", "home_score"):
            if key in score:
                home = safe_score_value(score.get(key))
                break
        for key in ("away", "awayScore", "away_score"):
            if key in score:
                away = safe_score_value(score.get(key))
                break
        if home is not None and away is not None:
            return home, away

    return None, None


def incident_phase_rank(incident):
    """Classe un événement dans la chronologie FOOTSCAN.

    Chronologie normale et lecture de reconstitution: 0-0 < temps réglementaire
    < prolongation < tirs au but. Les tirs au but de séance sont traités comme
    une même phase/minute.
    """
    if not isinstance(incident, dict):
        return 1

    texts = []
    for key in ("incidentType", "incidentClass", "type", "class", "period", "phase", "description", "reason", "text"):
        value = incident.get(key)
        if value is not None:
            texts.append(normalize_status_text(value))
    haystack = " | ".join(texts)

    # Attention: un penalty dans le temps réglementaire ne doit pas devenir
    # séance de tirs au but. On cherche surtout shootout/penalties.
    if "shootout" in haystack or "penalties" in haystack or "penalty shoot" in haystack or "tirs au but" in haystack or "tir au but" in haystack:
        return 3
    if "period5" in haystack or "penaltyshootout" in haystack or "penalty-shootout" in haystack:
        return 3

    if "extra time" in haystack or "overtime" in haystack or "prolongation" in haystack or "period3" in haystack or "period4" in haystack:
        return 2

    minute = incident.get("time")
    added = incident.get("addedTime") or 0
    try:
        minute_value = float(minute)
    except Exception:
        minute_value = None

    # Si SofaScore encode le temps additionnel réglementaire sous forme
    # time=90, addedTime=8, cela reste du temps réglementaire.
    try:
        added_value = float(added or 0)
    except Exception:
        added_value = 0

    if minute_value is None:
        return 3 if "penalt" in haystack else 1
    if minute_value > 90 and added_value <= 0:
        return 2
    return 1


def incident_is_within_regulation_time(incident):
    return incident_phase_rank(incident) == 1


def incident_reconstruction_chrono_key(incident):
    phase = incident_phase_rank(incident)
    minute = incident.get("time") if isinstance(incident, dict) else 0
    added = incident.get("addedTime") if isinstance(incident, dict) else 0
    try:
        minute_value = int(float(minute or 0))
    except Exception:
        minute_value = 0
    try:
        added_value = int(float(added or 0))
    except Exception:
        added_value = 0

    if phase == 3:
        return (3, 0, 0, 0)
    if phase == 2:
        return (2, minute_value, added_value, 0)
    regular_key = trend_goal_chrono_key(minute_value, added_value)
    return (1, regular_key[0], regular_key[1], regular_key[2])


def incident_reconstruction_average_minute(incident):
    phase = incident_phase_rank(incident)
    minute = incident.get("time") if isinstance(incident, dict) else 0
    added = incident.get("addedTime") if isinstance(incident, dict) else 0
    try:
        minute_value = float(minute or 0)
    except Exception:
        minute_value = 0.0
    try:
        added_value = float(added or 0)
    except Exception:
        added_value = 0.0
    if phase == 3:
        return 130.0
    if phase == 2:
        return max(91.0, minute_value + added_value)
    return trend_goal_average_minute(minute_value, added_value)


def incident_reconstruction_minute_label(incident):
    phase = incident_phase_rank(incident)
    if phase == 3:
        return "TAB"
    minute = incident.get("time") if isinstance(incident, dict) else 0
    added = incident.get("addedTime") if isinstance(incident, dict) else 0
    label = trend_goal_minute_label(minute, added)
    if phase == 2:
        return f"P {label}"
    return label


def collect_reconstruction_goal_entries(match, incidents, analyzed_team_id, include_extra=False, regulation_time_limit=True):
    """Prépare les états de score d'un vrai match pour la reconstitution.

    Chaque vrai match contient un état initial 0-0 à la minute 0. Pour chaque
    but, on conserve le score exact au moment de l'événement, normalisé du
    point de vue de l'équipe analysée. Une reconstitution utilisera ensuite ces
    états selon le mode Séquence ou Escalier, sans jamais réutiliser le même
    état de score.
    """
    match_label = make_match_label(match)
    match_id = match.get("id")
    competition = get_competition_name(match)
    start_timestamp = match.get("startTimestamp") or 0
    final_home_score, final_away_score = match_score_pair(match, regulation_time_limit=regulation_time_limit)
    final_score_total = match_score_total(match, regulation_time_limit=regulation_time_limit)
    true_zero_zero = final_score_total == 0 if final_score_total is not None else False
    source_score_label = f"{final_home_score}-{final_away_score}" if final_home_score is not None and final_away_score is not None else "Score inconnu"
    match_has_assists = match_contains_goal_assist(incidents)
    extra_time_penalty_issue = (not include_extra) and incidents_indicate_extra_time_or_penalty(incidents)
    goals = []

    home_id = ((match.get("homeTeam") or {}).get("id"))
    analyzed_is_home = home_id == analyzed_team_id
    running_home = 0
    running_away = 0

    goal_incidents = []
    for inc in incidents or []:
        if not isinstance(inc, dict) or inc.get("incidentType") != "goal":
            continue
        minute = inc.get("time")
        phase_rank = incident_phase_rank(inc)
        if phase_rank > 1 and not include_extra:
            continue
        if regulation_time_limit and not incident_is_within_regulation_time(inc):
            continue
        if phase_rank == 1 and (minute is None or float(minute) < 1):
            continue
        goal_incidents.append(inc)

    goal_incidents.sort(key=incident_reconstruction_chrono_key)

    for inc in goal_incidents:
        minute = inc.get("time")
        added = inc.get("addedTime") or 0
        own_goal = is_own_goal_incident(inc)
        if own_goal:
            goal_for_team = not own_goal_committed_by_analyzed_team(inc, match, analyzed_team_id)
        else:
            scorer_is_analyzed = incident_belongs_to_analyzed_team(inc, match, analyzed_team_id)
            goal_for_team = scorer_is_analyzed

        incident_home, incident_away = incident_score_pair(inc)
        if incident_home is not None and incident_away is not None:
            running_home = incident_home
            running_away = incident_away
        else:
            if goal_for_team:
                if analyzed_is_home:
                    running_home += 1
                else:
                    running_away += 1
            else:
                if analyzed_is_home:
                    running_away += 1
                else:
                    running_home += 1

        team_score = running_home if analyzed_is_home else running_away
        opponent_score = running_away if analyzed_is_home else running_home
        attack_score = team_score
        opponent_attack_score = opponent_score
        index_chrono = len(goals) + 1
        try:
            clean_minute = int(float(minute or 0))
        except Exception:
            clean_minute = 0
        try:
            clean_added = int(float(added or 0))
        except Exception:
            clean_added = 0

        goals.append({
            "isZeroZero": False,
            "minute": clean_minute,
            "added": clean_added,
            "minuteLabel": incident_reconstruction_minute_label(inc),
            "averageMinute": incident_reconstruction_average_minute(inc),
            "chronoKey": incident_reconstruction_chrono_key(inc),
            "phaseRank": incident_phase_rank(inc),
            "goalDelta": 1 if goal_for_team else -1,
            "attackDelta": 1 if goal_for_team and not own_goal else 0,
            "opponentAttackDelta": 0 if goal_for_team or own_goal else 1,
            "goalForTeam": bool(goal_for_team),
            "ownGoal": bool(own_goal),
            "teamScore": float(team_score),
            "opponentScore": float(opponent_score),
            "attackScore": float(attack_score),
            "opponentAttackScore": float(opponent_attack_score),
            "scoreStateLabel": f"{reconstruction_number_label(team_score)}-{reconstruction_number_label(opponent_score)}",
            "homeScoreAtEvent": running_home,
            "awayScoreAtEvent": running_away,
            "stateKey": f"goal-{index_chrono}",
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

    goal_data_complete = True
    if final_score_total is not None and final_score_total > len(goals):
        goal_data_complete = False

    zero_zero = {
        "isZeroZero": True,
        "minute": 0,
        "added": 0,
        "minuteLabel": "0'",
        "averageMinute": 0.0,
        "chronoKey": (0, 0, 0, 0),
        "goalDelta": 0,
        "attackDelta": 0,
        "opponentAttackDelta": 0,
        "goalForTeam": None,
        "ownGoal": False,
        "teamScore": 0.0,
        "opponentScore": 0.0,
        "attackScore": 0.0,
        "opponentAttackScore": 0.0,
        "scoreStateLabel": "0-0",
        "homeScoreAtEvent": 0,
        "awayScoreAtEvent": 0,
        "stateKey": "zero-zero",
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
        "extraTimePenaltyIssue": bool(extra_time_penalty_issue),
        "matchHasAssists": match_has_assists,
        "assistDataStatus": "assist-found" if match_has_assists else "no-assist-found",
    }

def reconstruction_source_is_true_zero_zero(source_record):
    if not reconstruction_source_is_complete(source_record):
        return False
    return bool(source_record.get("trueZeroZero"))


def reconstruction_entry_uid(entry):
    if not isinstance(entry, dict):
        return None
    match_id = entry.get("sourceMatchId")
    state_key = entry.get("stateKey") or ("zero-zero" if entry.get("isZeroZero") else entry.get("minuteLabel"))
    return f"{match_id}:{state_key}"


def reconstruction_source_entry(source_record, minimum_index_from_end=1, used_keys=None):
    """Retourne le prochain état de score exploitable pour un vrai match.

    minimum_index_from_end respecte la diagonale: M1 dernier score, M2
    avant-dernier score, M3 troisième depuis la fin, etc. Si ce rang n'existe
    plus dans les buts, on tombe sur le 0-0 minute 0. Les états déjà utilisés
    sont ignorés: aucun but ni 0-0 ne peut servir deux fois.
    """
    if not reconstruction_source_is_complete(source_record):
        return None

    used = set(used_keys or set())
    goals = source_record.get("goals") or []
    minimum_rank = max(1, int(minimum_index_from_end or 1))

    for rank in range(minimum_rank, len(goals) + 1):
        entry = dict(goals[-rank])
        entry["reconstructionSourceIndex"] = rank
        entry["reconstructionSourceGoalCount"] = len(goals)
        uid = reconstruction_entry_uid(entry)
        if uid not in used:
            entry["reconstructionUid"] = uid
            return entry

    zero = dict(source_record.get("zeroZero") or {})
    if zero:
        zero["reconstructionSourceIndex"] = len(goals) + 1
        zero["reconstructionSourceGoalCount"] = len(goals)
        uid = reconstruction_entry_uid(zero)
        if uid not in used:
            zero["reconstructionUid"] = uid
            return zero

    return None


def reconstruction_entry_keeps_reverse_chronology(previous_entry, next_entry):
    """La reconstitution remonte le match: le prochain score doit être antérieur.

    Une minute de 1re mi-temps en temps additionnel reste donc valide après un
    but de 2e mi-temps, par exemple 46 puis 45+3. Le 0-0 minute 0 clôture la
    reconstitution et reste toujours chronologiquement valide.
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


def build_reconstructed_trend_sample(entries, analyzed_team_id, level_mode="full", index=1, reconstruction_mode="sequence"):
    clean_entries = [entry for entry in entries or [] if isinstance(entry, dict)]
    zero_only = len(clean_entries) == 1 and bool(clean_entries[0].get("isZeroZero"))

    team_scores = [float(entry.get("teamScore") or 0.0) for entry in clean_entries]
    opponent_scores = [float(entry.get("opponentScore") or 0.0) for entry in clean_entries]
    attack_scores = [float(entry.get("attackScore", entry.get("teamScore") or 0.0) or 0.0) for entry in clean_entries]
    opponent_attack_scores = [float(entry.get("opponentAttackScore", entry.get("opponentScore") or 0.0) or 0.0) for entry in clean_entries]

    avg_team_score = reconstruction_score_average(team_scores)
    avg_opponent_score = reconstruction_score_average(opponent_scores)
    avg_attack_score = reconstruction_score_average(attack_scores)
    avg_opponent_attack_score = reconstruction_score_average(opponent_attack_scores)

    # Camp Combiné: les scores de reconstitution sont récupérés sans défense.
    # On conserve le score offensif au moment de chaque événement, mais le côté
    # défensif/adverse n'entre plus dans la moyenne ni dans la formule combinée.
    attack_only_without_defense = str(level_mode or "").strip().lower() == "attack"
    if attack_only_without_defense:
        avg_opponent_score = 0.0
        avg_opponent_attack_score = 0.0

    all_state_minutes = [float(entry.get("averageMinute") or 0.0) for entry in clean_entries]
    attack_state_minutes = [float(entry.get("averageMinute") or 0.0) for entry in clean_entries]
    opponent_attack_minutes = [float(entry.get("averageMinute") or 0.0) for entry in clean_entries]

    if level_mode == "attack":
        level = avg_attack_score
        minutes_for_average = attack_state_minutes[:] if attack_state_minutes else [0.0]
    else:
        level = avg_team_score - avg_opponent_score
        minutes_for_average = all_state_minutes[:] if all_state_minutes else [0.0]

    label = compact_reconstruction_label(clean_entries)
    first_entry = clean_entries[0] if clean_entries else {}
    last_entry = clean_entries[-1] if clean_entries else first_entry
    source_ids = [str(entry.get("sourceMatchId")) for entry in clean_entries if entry.get("sourceMatchId") is not None]
    sample_id = f"reconstitution-{analyzed_team_id}-{index}-" + "-".join(source_ids[:4])

    match_has_assists = any(bool(entry.get("matchHasAssists")) for entry in clean_entries)
    assist_status = "assist-found" if match_has_assists else "no-assist-found"
    opponent_minutes_for_average = opponent_attack_minutes[:] if opponent_attack_minutes else [0.0]

    full_score_label = f"{reconstruction_number_label(avg_team_score)}-{reconstruction_number_label(avg_opponent_score)}"
    attack_score_label = f"Attaque {reconstruction_number_label(avg_attack_score)}"
    opponent_attack_score_label = f"Attaque adverse {reconstruction_number_label(avg_opponent_attack_score)}"

    if level_mode == "attack":
        reconstruction_score_label = attack_score_label
        reconstruction_display_label = f"Reconstitution {index} · {reconstruction_score_label}"
    else:
        reconstruction_score_label = full_score_label
        reconstruction_display_label = f"Reconstitution {index} · {reconstruction_score_label}"

    return {
        "id": sample_id,
        "label": label,
        "reconstructionLabel": label,
        "reconstructionDisplayLabel": reconstruction_display_label,
        "reconstructionScoreLabel": reconstruction_score_label,
        "reconstructionFullScoreLabel": full_score_label,
        "reconstructionAttackScoreLabel": attack_score_label,
        "reconstructionScoreAverage": {
            "team": round(avg_team_score, 6),
            "opponent": round(avg_opponent_score, 6),
            "attack": round(avg_attack_score, 6),
            "opponentAttack": round(avg_opponent_attack_score, 6),
        },
        "competition": first_entry.get("sourceCompetition") or last_entry.get("sourceCompetition") or "Reconstitution",
        "startTimestamp": first_entry.get("sourceStartTimestamp") or last_entry.get("sourceStartTimestamp") or 0,
        "homeTeam": {},
        "awayTeam": {},
        "analyzedTeamId": analyzed_team_id,
        "goalsFor": round(avg_team_score, 6),
        "goalsAgainst": round(avg_opponent_score, 6),
        "attackGoalsFor": round(avg_attack_score, 6),
        "level": round(level, 6),
        "levelMode": level_mode,
        "defenseRemovedForCombined": bool(attack_only_without_defense),
        "resultStyle": trend_result_style(level),
        "resultLabel": trend_label_from_style(trend_result_style(level)),
        "goalMinutes": all_state_minutes,
        "attackGoalMinutes": attack_state_minutes,
        "minutesForAverage": minutes_for_average,
        "averageMinute": round(trend_average(minutes_for_average), 4),
        "matchHasAssists": match_has_assists,
        "assistDataStatus": assist_status,
        "eventDataStatus": "ok",
        "reconstructedMatch": True,
        "reconstructionMethod": reconstruction_mode,
        "reconstructionIndex": index,
        "reconstructionZeroOnly": zero_only,
        "reconstructionEntries": [
            {
                "sourceMatchId": entry.get("sourceMatchId"),
                "sourceLabel": entry.get("sourceLabel"),
                "sourceCompetition": entry.get("sourceCompetition"),
                "sourceStartTimestamp": entry.get("sourceStartTimestamp") or 0,
                "sourceScoreLabel": entry.get("sourceScoreLabel"),
                "scoreStateLabel": entry.get("scoreStateLabel"),
                "teamScore": entry.get("attackScore") if attack_only_without_defense else entry.get("teamScore"),
                "opponentScore": 0.0 if attack_only_without_defense else entry.get("opponentScore"),
                "attackScore": entry.get("attackScore"),
                "opponentAttackScore": 0.0 if attack_only_without_defense else entry.get("opponentAttackScore"),
                "homeScoreAtEvent": entry.get("homeScoreAtEvent"),
                "awayScoreAtEvent": entry.get("awayScoreAtEvent"),
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
                "stateKey": entry.get("stateKey"),
            }
            for entry in clean_entries
        ],
        "opponentAttack": {
            "id": f"{sample_id}-opponent-attack",
            "label": label,
            "reconstructionLabel": label,
            "reconstructionDisplayLabel": f"Reconstitution {index} · {opponent_attack_score_label}",
            "reconstructionScoreLabel": opponent_attack_score_label,
            "competition": first_entry.get("sourceCompetition") or last_entry.get("sourceCompetition") or "Reconstitution",
            "startTimestamp": first_entry.get("sourceStartTimestamp") or last_entry.get("sourceStartTimestamp") or 0,
            "level": round(avg_opponent_attack_score, 6),
            "attackGoalsFor": round(avg_opponent_attack_score, 6),
            "minutesForAverage": [] if attack_only_without_defense else opponent_minutes_for_average,
            "averageMinute": round(trend_average(opponent_minutes_for_average), 4) if not attack_only_without_defense else 0.0,
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
                    "scoreStateLabel": entry.get("scoreStateLabel"),
                    "teamScore": entry.get("attackScore") if attack_only_without_defense else entry.get("teamScore"),
                    "opponentScore": 0.0 if attack_only_without_defense else entry.get("opponentScore"),
                    "opponentAttackScore": 0.0 if attack_only_without_defense else entry.get("opponentAttackScore"),
                    "minuteLabel": entry.get("minuteLabel"),
                    "isZeroZero": bool(entry.get("isZeroZero")),
                    "matchHasAssists": entry.get("matchHasAssists"),
                    "assistDataStatus": entry.get("assistDataStatus"),
                    "stateKey": entry.get("stateKey"),
                }
                for entry in clean_entries
            ],
        },
    }

def build_reconstructed_trend_samples(source_records, analyzed_team_id, level_mode="full", reconstruction_mode="sequence", max_samples=None):
    """Reconstruit des matchs uniquement à partir de vrais états de score.

    Mode Séquence : ancien principe linéaire, mais avec le 0-0 minute 0 commun.
    Mode Escalier : après chaque reconstitution, on revient au premier vrai match
    encore exploitable; M1 fournit le dernier score disponible, M2 l'avant-dernier,
    M3 le troisième depuis la fin, etc. Aucun score d'événement ni 0-0 minute 0
    ne peut être utilisé deux fois.
    """
    normalized_mode = str(reconstruction_mode or "sequence").strip().lower()
    if normalized_mode in {"sequence", "séquence", "seq"}:
        normalized_mode = "sequence"
    else:
        normalized_mode = "staircase"

    records = [record for record in (source_records or []) if reconstruction_source_is_complete(record)]
    limit = None
    try:
        if max_samples is not None:
            limit = int(max_samples)
    except Exception:
        limit = None

    def append_sample(samples, entries):
        if not entries:
            return
        samples.append(build_reconstructed_trend_sample(
            entries,
            analyzed_team_id,
            level_mode=level_mode,
            index=len(samples) + 1,
            reconstruction_mode=normalized_mode,
        ))

    if normalized_mode == "sequence":
        samples = []
        used = set()
        current = []
        previous_entry = None
        source_index = 0
        score_index_from_end = 1

        def close_current():
            nonlocal current, previous_entry, score_index_from_end
            append_sample(samples, current)
            current = []
            previous_entry = None
            score_index_from_end = 1

        while source_index < len(records):
            if limit is not None and len(samples) >= limit:
                break

            source_record = records[source_index]
            entry = reconstruction_source_entry(source_record, score_index_from_end, used)

            if not entry:
                if current:
                    close_current()
                    continue
                source_index += 1
                score_index_from_end = 1
                continue

            if current and not reconstruction_entry_keeps_reverse_chronology(previous_entry, entry):
                close_current()
                current = [entry]
                uid = reconstruction_entry_uid(entry)
                if uid:
                    used.add(uid)
                if entry.get("isZeroZero"):
                    close_current()
                    source_index += 1
                    continue
                previous_entry = entry
                source_index += 1
                score_index_from_end = 2
                continue

            current.append(entry)
            uid = reconstruction_entry_uid(entry)
            if uid:
                used.add(uid)

            if entry.get("isZeroZero"):
                close_current()
                source_index += 1
                continue

            previous_entry = entry
            source_index += 1
            score_index_from_end += 1

        if limit is None or len(samples) < limit:
            close_current()
        return samples

    samples = []
    used = set()
    start_index = 0
    safety = 0
    max_safety = max(1000, len(records) * 50 + 50)

    def start_can_provide(index):
        if index < 0 or index >= len(records):
            return False
        return reconstruction_source_entry(records[index], 1, used) is not None

    while start_index < len(records) and safety < max_safety:
        safety += 1
        if limit is not None and len(samples) >= limit:
            break

        while start_index < len(records) and not start_can_provide(start_index):
            start_index += 1
        if start_index >= len(records):
            break

        current = []
        previous_entry = None
        source_index = start_index
        offset = 0

        while source_index < len(records):
            entry = reconstruction_source_entry(records[source_index], offset + 1, used)
            if not entry:
                break

            if current and not reconstruction_entry_keeps_reverse_chronology(previous_entry, entry):
                break

            current.append(entry)
            uid = reconstruction_entry_uid(entry)
            if uid:
                used.add(uid)

            if entry.get("isZeroZero"):
                break

            previous_entry = entry
            source_index += 1
            offset += 1

        if current:
            append_sample(samples, current)
        else:
            start_index += 1

    return samples

def renumber_reconstructed_samples_chronologically(samples):
    """Renumérote une sélection du plus ancien (R1) au plus récent (Rn)."""
    output = []
    for index, source in enumerate(samples or [], start=1):
        sample = dict(source or {})
        sample["reconstructionIndex"] = index
        score_label = sample.get("reconstructionScoreLabel") or reconstruction_number_label(sample.get("level") or 0)
        sample["reconstructionDisplayLabel"] = f"Reconstitution {index} · {score_label}"

        opponent_attack = sample.get("opponentAttack")
        if isinstance(opponent_attack, dict):
            opponent_attack = dict(opponent_attack)
            opponent_score_label = opponent_attack.get("reconstructionScoreLabel") or reconstruction_number_label(opponent_attack.get("level") or 0)
            opponent_attack["reconstructionDisplayLabel"] = f"Reconstitution {index} · {opponent_score_label}"
            sample["opponentAttack"] = opponent_attack

        output.append(sample)
    return output

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
        defense_removed = bool(direct.get("defenseRemovedForCombined"))

        direct_minutes = list(direct.get("minutesForAverage") or [1.0])
        direct_score_label = direct.get("reconstructionAttackScoreLabel") or direct.get("reconstructionScoreLabel") or format(direct_level, ".6g")

        if defense_removed:
            adv_level = 0.0
            adv_minutes = []
            level = direct_level
            minutes_for_average = direct_minutes
            opponent_score_label = "Défense retirée"
            combined_formula_label = f"{direct_score_label} · sans défense"
            combined_score_label = direct_score_label
        else:
            adv_level = float(opponent_attack.get("level") or 0)
            level = direct_level + adv_level
            adv_minutes = list(opponent_attack.get("minutesForAverage") or [1.0])
            minutes_for_average = direct_minutes + adv_minutes
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
                "averageMinute": round(trend_average(adv_minutes), 4) if adv_minutes else 0.0,
                "matchHasAssists": opponent_attack.get("matchHasAssists", source.get("matchHasAssists")),
                "assistDataStatus": opponent_attack.get("assistDataStatus", source.get("assistDataStatus")),
                "reconstructionEntries": [] if defense_removed else (opponent_attack.get("reconstructionEntries") or source.get("reconstructionEntries") or []),
            },
            "analysisFormula": "attaque équipe sans défense" if defense_removed else "attaque équipe + attaque adversaire du camp opposé",
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
            "scoreStateLabel": entry.get("scoreStateLabel") or ("0-0" if entry.get("isZeroZero") else None),
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


def fetch_trend_team_matches(job_id, analyzed_team_id, skip, trend_count, team_name, base_progress, progress_span, level_mode="full", reconstruction_mode="sequence", include_extra=False, regulation_time_limit=True):
    needed_matches = max(1, int(trend_count))
    pages = []
    stopped_history = False
    administrative_matches_ignored = {}
    pages_loaded_count = 0
    pages_attempted_count = 0

    window_base = RECONSTRUCTION_WINDOW_BASE_MATCHES
    window_max = RECONSTRUCTION_WINDOW_MAX_MATCHES
    window_target = window_base

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
            admin_reason = administrative_match_reason(match, include_extra=include_extra)
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
                    message=f"{team_name} · Reconstitution · Page {page + 1}/{target_pages}",
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
    samples = []
    sorted_matches = []

    # Le filtre Extra est déjà appliqué dans build_finished_matches. Ignorer
    # matchs s'applique ensuite aux sources complètes, puis la fenêtre retient
    # les 30 matchs admissibles les plus récents (40 seulement si nécessaire).
    raw_buffer = max(8, skip + 4)
    required = skip + window_target + raw_buffer

    def make_latest_samples(effective_records, target_window):
        # effective_records est déjà classé du plus récent au plus ancien.
        # On garde la fenêtre la plus proche du présent et on reconstitue dans
        # ce même sens: dernier match vers ancien, dernier score vers ancien.
        window_desc = list(effective_records[skip:skip + target_window])
        reconstructed = build_reconstructed_trend_samples(
            window_desc,
            analyzed_team_id,
            level_mode=level_mode,
            reconstruction_mode=reconstruction_mode,
            max_samples=needed_matches,
        )
        return reconstructed[:needed_matches]

    while True:
        by_id = load_until_required(required)
        sorted_matches = sorted(
            by_id.values(),
            key=lambda m: (m.get("startTimestamp") or 0, m.get("id") or 0),
            reverse=True,
        )
        selected_matches = sorted_matches[:required]
        total_sources = len(selected_matches)

        for idx in range(len(source_records), total_sources):
            match = selected_matches[idx]
            update_scan_job(
                job_id,
                status="running",
                message=f"{team_name} · Reconstitution · Source {idx + 1}/{total_sources}",
                progress=base_progress + int(progress_span * (0.15 + 0.80 * ((idx + 1) / max(1, total_sources)))),
            )
            try:
                data = get_incidents_json(f"event/{match['id']}/incidents")
            except Exception as e:
                err_text = str(e)
                data = {
                    "_footscanIssue": {
                        "type": "missing" if ("HTTP 404" in err_text or "Not Found" in err_text) else ("blocked" if ("challenge" in err_text or "HTTP 403" in err_text) else "error"),
                        "reason": err_text,
                        "message": "Reconstitution non valide: événements/buts non récupérables pour ce match.",
                    },
                    "incidents": [],
                }

            issue = data.get("_footscanIssue") if isinstance(data, dict) else None
            incidents = data.get("incidents") if isinstance(data, dict) else data
            if not isinstance(incidents, list):
                incidents = []
            source_record = collect_reconstruction_goal_entries(
                match,
                incidents,
                analyzed_team_id,
                include_extra=include_extra,
                regulation_time_limit=regulation_time_limit,
            )
            if source_record.get("extraTimePenaltyIssue"):
                source_record["eventDataStatus"] = "extra-time-penalties"
                source_record["eventDataIssue"] = True
                source_record["error"] = "Prolongation ou tirs au but exclus de l'analyse"
                event_data_issues.append({
                    "id": match.get("id"),
                    "label": make_match_label(match),
                    "competition": get_competition_name(match),
                    "startTimestamp": match.get("startTimestamp") or 0,
                    "type": "extra-time-penalties",
                    "reason": "Prolongation ou tirs au but détectés dans les événements",
                    "message": "Match ignoré pour la reconstitution: prolongation ou tirs au but exclus de l'analyse.",
                })
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
                source_record["eventDataStatus"] = "ok-zero-zero"
            elif source_record.get("reconstructionGoalsIncomplete"):
                source_record["eventDataStatus"] = "incomplete-goals"
                source_record["eventDataIssue"] = True
                source_record["error"] = "Reconstitution non valide: score non nul sans buts récupérables complets"
                event_data_issues.append({
                    "id": match.get("id"),
                    "label": make_match_label(match),
                    "competition": get_competition_name(match),
                    "startTimestamp": match.get("startTimestamp") or 0,
                    "type": "incomplete-goals",
                    "reason": "Reconstitution non valide: score non nul sans buts récupérables complets",
                    "message": "Reconstitution non valide: le score du match est non nul mais les buts récupérables sont absents ou incomplets.",
                })
            source_records.append(source_record)

            effective = [record for record in source_records if reconstruction_source_is_complete(record)]
            usable_after_skip = max(0, len(effective) - skip)
            if usable_after_skip >= window_target:
                samples = make_latest_samples(effective, window_target)
                if len(samples) >= needed_matches:
                    break
                if window_target < window_max:
                    window_target = window_max
                    required = max(required, skip + window_target + raw_buffer)
                else:
                    raise RuntimeError(
                        f"{team_name}: pas assez de reconstitutions dans la plage maximale "
                        f"de {window_max} matchs ({len(samples)}/{needed_matches})."
                    )

        if len(samples) >= needed_matches:
            break

        effective = [record for record in source_records if reconstruction_source_is_complete(record)]
        usable_after_skip = max(0, len(effective) - skip)

        if usable_after_skip >= window_target:
            samples = make_latest_samples(effective, window_target)
            if len(samples) >= needed_matches:
                break
            if window_target < window_max:
                window_target = window_max
                required = max(required, skip + window_target + raw_buffer)
                continue
            raise RuntimeError(
                f"{team_name}: pas assez de reconstitutions dans la plage maximale "
                f"de {window_max} matchs ({len(samples)}/{needed_matches})."
            )

        history_exhausted = bool(stopped_history or next_page >= PAGES_TO_LOAD)
        all_known_sources_processed = len(source_records) >= len(sorted_matches)
        if history_exhausted and all_known_sources_processed:
            # Même si moins de 30 matchs existent, on tente la plage disponible.
            available_window = min(window_max, usable_after_skip)
            if available_window > 0:
                samples = make_latest_samples(effective, available_window)
            if len(samples) >= needed_matches:
                break
            raise RuntimeError(
                f"{team_name}: pas assez de reconstitutions dans la plage historique "
                f"({len(samples)}/{needed_matches}, matchs utilisables: {usable_after_skip}, "
                f"plage maximale: {window_max})."
            )

        # Plus de sources brutes sont nécessaires à cause de matchs incomplets.
        required += max(8, min(20, window_max // 2))

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
        "reconstructionWindowBase": window_base,
        "reconstructionWindowUsed": min(window_target, max(0, len([record for record in source_records if reconstruction_source_is_complete(record)]) - skip)),
        "reconstructionWindowMax": window_max,
        "reconstructionDirection": "newest_to_oldest",
        "displayDirection": "newest_to_oldest",
        "scanPartial": False,
    }

def build_trend_items(samples, side_key, trend_count, trend_limit_enabled=False):
    items = []
    for i in range(int(trend_count)):
        recent = samples[i]
        previous = samples[i + 1]
        # Sens d'origine: niveau de la reconstitution récente comparé à l'ancienne.
        raw_trend_value = (recent.get("level") or 0) - (previous.get("level") or 0)
        trend_value = max(-2.0, min(2.0, float(raw_trend_value))) if trend_limit_enabled else raw_trend_value
        trend_was_limited = bool(trend_limit_enabled and float(raw_trend_value) != float(trend_value))
        previous_minutes = previous.get("minutesForAverage") or [1]
        recent_minutes = recent.get("minutesForAverage") or [1]
        previous_avg_minute = trend_average(previous_minutes)
        recent_avg_minute = trend_average(recent_minutes)
        average_minute_progression = recent_avg_minute - previous_avg_minute
        # Moyenne minute de la tendance = moyenne des 2 reconstitutions comparées.
        # Chaque reconstitution garde le même poids, peu importe son nombre de buts.
        minutes = [recent_avg_minute, previous_avg_minute]
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
                progression = previous_avg - recent_avg
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
        return (-float(entry.get("progression") or 0), float(entry.get("averageMinute") or 9999))

    def same_best(a, b):
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
    metric_label = "Progression Moyenne"

    if total <= 0:
        return {
            "method": normalized_mode,
            "label": label,
            "selectionMetric": normalized_metric,
            "selectionMetricLabel": metric_label,
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
        "selectionMetricLabel": metric_label,
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

    # La performance finale est la moyenne pondérée des tendances réellement prises.
    raw_performance_score = performance_score
    final_performance_score = (raw_performance_score / dominant_count) if dominant_count > 0 else 0.0
    result_profile = build_result_profile(counts, apply_variance=True)

    return {
        "performanceScore": round(final_performance_score, 6),
        "rawPerformanceScore": round(raw_performance_score, 6),
        "performanceSum": round(raw_performance_score, 6),
        "performanceAverageDivisor": normalize_trend_count(dominant_count),
        "performanceAverageApplied": True,
        "performanceVarianceApplied": False,
        **result_profile,
        "dominantCount": normalize_trend_count(dominant_count),
    }

def reconstruction_goal_quantity(sample):
    """Quantité de buts utilisée pour choisir la reconstitution la plus offensive."""
    if not isinstance(sample, dict):
        return 0.0
    score_average = sample.get("reconstructionScoreAverage") or {}
    level_mode = str(sample.get("levelMode") or "").strip().lower()
    if level_mode in {"attack", "separated-attack-vs-attack"} or sample.get("defenseRemovedForCombined"):
        value = sample.get("attackGoalsFor", score_average.get("attack", sample.get("goalsFor", 0)))
    else:
        value = sample.get("goalsFor", score_average.get("team", 0))
    try:
        number = float(value or 0)
    except Exception:
        number = 0.0
    return number if math.isfinite(number) else 0.0


def summarize_reconstruction_samples(samples):
    clean = [sample for sample in (samples or []) if isinstance(sample, dict)]
    if not clean:
        return {
            "meanScore": 0.0,
            "tendencyScore": 0.0,
            "reconstructionCount": 0,
            "highestMinuteIndex": None,
            "highestGoalsIndex": None,
            "highestMinuteValue": 0.0,
            "highestGoalsValue": 0.0,
            "highestMinuteReconstruction": None,
            "highestGoalsReconstruction": None,
            "performanceScore": 0.0,
            "dominantCount": 0,
        }

    levels = [float(sample.get("level") or 0.0) for sample in clean]
    mean_score = sum(levels) / len(levels)

    # Les échantillons sont classés du plus récent au plus ancien. En cas
    # d'égalité de critère, le premier garde donc la priorité (le plus récent).
    minute_index = max(range(len(clean)), key=lambda idx: float(clean[idx].get("averageMinute") or 0.0))
    goals_index = max(range(len(clean)), key=lambda idx: reconstruction_goal_quantity(clean[idx]))
    minute_sample = clean[minute_index]
    goals_sample = clean[goals_index]
    tendency_score = (float(minute_sample.get("level") or 0.0) + float(goals_sample.get("level") or 0.0)) / 2.0

    return {
        "meanScore": round(mean_score, 6),
        "tendencyScore": round(tendency_score, 6),
        "reconstructionCount": len(clean),
        "highestMinuteIndex": minute_index + 1,
        "highestGoalsIndex": goals_index + 1,
        "highestMinuteValue": round(float(minute_sample.get("averageMinute") or 0.0), 4),
        "highestGoalsValue": round(reconstruction_goal_quantity(goals_sample), 6),
        "highestMinuteReconstruction": minute_sample,
        "highestGoalsReconstruction": goals_sample,
        # Compatibilité avec l'ancien rendu : la « performance » est désormais
        # la Tendance calculée depuis les deux reconstitutions repères.
        "performanceScore": round(tendency_score, 6),
        "dominantCount": len(clean),
    }


def process_trend_scan_job(job_id, params):
    match_id = str(params.get("matchId") or "").strip()
    reconstruction_count = int(float(params.get("reconstructionCount") or params.get("trendCount") or params.get("rank1") or 9))
    reconstruction_count = max(1, min(100, reconstruction_count))
    skip_home = int(params.get("skipHome") or 0)
    skip_away = int(params.get("skipAway") or 0)
    simultaneous_mode = True if params.get("simultaneousMode") is None else truthy_param(params.get("simultaneousMode"))
    include_extra_raw = params.get("includeExtra") if params.get("includeExtra") is not None else params.get("includeExtraEnabled")
    include_extra = True if include_extra_raw is None else truthy_param(include_extra_raw)
    regulation_time_limit = True if params.get("regulationTimeLimitEnabled") is None else truthy_param(params.get("regulationTimeLimitEnabled"))
    reconstruction_mode = str(params.get("reconstructionMode") or "sequence").strip().lower()
    reconstruction_mode = "sequence" if reconstruction_mode in {"sequence", "séquence", "seq"} else "staircase"
    reconstruction_mode_label = "Séquence" if reconstruction_mode == "sequence" else "Escalier"

    trend_to_mean_enabled = truthy_param(params.get("trendToMeanEnabled"))
    mean_to_trend_enabled = truthy_param(params.get("meanToTrendEnabled"))
    # Sécurité serveur : les deux sens sont exclusifs. Si un ancien client
    # envoie les deux, Tendance Vers Moyenne garde la priorité.
    if trend_to_mean_enabled:
        mean_to_trend_enabled = False
    variance_direction = (
        "trend_to_mean" if trend_to_mean_enabled else
        ("mean_to_trend" if mean_to_trend_enabled else "none")
    )
    variance_direction_label = {
        "trend_to_mean": "Tendance Vers Moyenne",
        "mean_to_trend": "Moyenne Vers Tendance",
        "none": "Tendance Directe",
    }[variance_direction]

    update_scan_job(job_id, status="running", message="Récupération Du Match Principal…", progress=5)
    match_data = get_json(f"event/{match_id}")
    match = match_data.get("event") if isinstance(match_data, dict) else match_data

    if not isinstance(match, dict) or not match.get("homeTeam") or not match.get("awayTeam"):
        raise RuntimeError("Format du match principal inattendu")

    home_team = match["homeTeam"]
    away_team = match["awayTeam"]
    needed_matches = reconstruction_count

    update_scan_job(
        job_id,
        status="running",
        message=f"Match trouvé : {home_team.get('name')} vs {away_team.get('name')} · {reconstruction_count} reconstitutions",
        progress=10,
    )

    level_mode = "full" if simultaneous_mode else "attack"

    home_scan = fetch_trend_team_matches(
        job_id, home_team["id"], skip_home, reconstruction_count,
        home_team.get("name") or "Domicile", 12, 40,
        level_mode=level_mode, reconstruction_mode=reconstruction_mode,
        include_extra=include_extra, regulation_time_limit=regulation_time_limit,
    )
    away_scan = fetch_trend_team_matches(
        job_id, away_team["id"], skip_away, reconstruction_count,
        away_team.get("name") or "Extérieur", 54, 40,
        level_mode=level_mode, reconstruction_mode=reconstruction_mode,
        include_extra=include_extra, regulation_time_limit=regulation_time_limit,
    )

    if not simultaneous_mode:
        home_combined = build_separated_offensive_samples(home_scan["trendMatches"], away_scan["trendMatches"], "home")
        away_combined = build_separated_offensive_samples(away_scan["trendMatches"], home_scan["trendMatches"], "away")
        home_scan["trendMatchesDirect"] = home_scan["trendMatches"]
        away_scan["trendMatchesDirect"] = away_scan["trendMatches"]
        home_scan["trendMatches"] = home_combined[:reconstruction_count]
        away_scan["trendMatches"] = away_combined[:reconstruction_count]
        home_scan["matchesUsed"] = rebuild_trend_matches_used_from_samples(home_scan["trendMatches"])
        away_scan["matchesUsed"] = rebuild_trend_matches_used_from_samples(away_scan["trendMatches"])
    else:
        home_scan["trendMatches"] = list(home_scan.get("trendMatches") or [])[:reconstruction_count]
        away_scan["trendMatches"] = list(away_scan.get("trendMatches") or [])[:reconstruction_count]

    if len(home_scan["trendMatches"]) < reconstruction_count or len(away_scan["trendMatches"]) < reconstruction_count:
        raise RuntimeError(
            f"Reconstitutions insuffisantes : {len(home_scan['trendMatches'])}/{reconstruction_count} domicile, "
            f"{len(away_scan['trendMatches'])}/{reconstruction_count} extérieur."
        )

    home_summary = summarize_reconstruction_samples(home_scan["trendMatches"])
    away_summary = summarize_reconstruction_samples(away_scan["trendMatches"])

    comparisons = []
    for index in range(reconstruction_count):
        home_sample = home_scan["trendMatches"][index]
        away_sample = away_scan["trendMatches"][index]
        comparisons.append({
            "index": index + 1,
            "home": home_sample,
            "away": away_sample,
            "minuteDiff": round(abs(float(home_sample.get("averageMinute") or 0) - float(away_sample.get("averageMinute") or 0)), 4),
        })

    def metric_for(summary):
        mean_score = float(summary.get("meanScore") or 0.0)
        tendency_score = float(summary.get("tendencyScore") or 0.0)
        if variance_direction == "trend_to_mean":
            return mean_score - tendency_score
        if variance_direction == "mean_to_trend":
            return tendency_score - mean_score
        return tendency_score

    def winner():
        h = metric_for(home_summary)
        a = metric_for(away_summary)
        eps = 1e-9
        close_gap_warning_threshold = 0.1111111111
        gap = abs(h - a)
        warning = gap < close_gap_warning_threshold
        common = {
            "mode": variance_direction,
            "modeLabel": variance_direction_label,
            "homeMetric": round(h, 6),
            "awayMetric": round(a, 6),
            "closeGapWarning": warning,
            "closeGapWarningThreshold": close_gap_warning_threshold,
        }
        if gap <= eps:
            return {
                **common,
                "type": "tie",
                "side": "tie",
                "label": "Égalité",
                "score": round((h + a) / 2, 6),
                "diff": 0,
            }
        if h > a:
            return {
                **common,
                "type": "winner",
                "side": "home",
                "label": home_team.get("name"),
                "score": round(h, 6),
                "diff": round(gap, 6),
            }
        return {
            **common,
            "type": "winner",
            "side": "away",
            "label": away_team.get("name"),
            "score": round(a, 6),
            "diff": round(gap, 6),
        }

    home_issue_count = int(home_scan.get("eventDataIssueCount") or 0)
    away_issue_count = int(away_scan.get("eventDataIssueCount") or 0)
    total_issue_count = home_issue_count + away_issue_count
    home_ignored_issue_count = int(home_scan.get("ignoredSourceIssueCount") or 0)
    away_ignored_issue_count = int(away_scan.get("ignoredSourceIssueCount") or 0)
    total_ignored_issue_count = home_ignored_issue_count + away_ignored_issue_count
    home_admin_count = int(home_scan.get("administrativeMatchCount") or 0)
    away_admin_count = int(away_scan.get("administrativeMatchCount") or 0)
    total_admin_count = home_admin_count + away_admin_count
    invalid_reconstruction_issues = [
        issue for issue in ((home_scan.get("ignoredSourceIssues") or []) + (away_scan.get("ignoredSourceIssues") or []))
        if isinstance(issue, dict) and str(issue.get("type") or "") in {"incomplete-goals", "missing", "blocked", "error"}
    ]
    invalid_reconstruction_issue_count = len(invalid_reconstruction_issues)

    result = {
        "trendMode": True,
        "reconstructionOnlyMode": True,
        "reconstructionCount": reconstruction_count,
        "trendCount": reconstruction_count,
        "trendCalculationCount": reconstruction_count,
        "trendMatchesNeeded": needed_matches,
        "simultaneousMode": simultaneous_mode,
        "scanModeLabel": "Camp Séparé" if simultaneous_mode else "Camp Combiné",
        "reconstructionMode": reconstruction_mode,
        "reconstructionModeLabel": reconstruction_mode_label,
        "trendLevelMode": level_mode,
        "includeExtra": bool(include_extra),
        "includeExtraEnabled": bool(include_extra),
        "regulationTimeLimitEnabled": bool(regulation_time_limit),
        "trendToMeanEnabled": bool(trend_to_mean_enabled),
        "meanToTrendEnabled": bool(mean_to_trend_enabled),
        "varianceDirection": variance_direction,
        "varianceDirectionLabel": variance_direction_label,
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
            "trend": {**home_summary, "items": home_scan["trendMatches"]},
            "r1": {"value": home_summary["tendencyScore"], "sources": []},
            "r2": None,
            "zoneStats": {"average": home_summary["meanScore"], "count": reconstruction_count},
        },
        "away": {
            **away_team,
            **away_scan,
            "trend": {**away_summary, "items": away_scan["trendMatches"]},
            "r1": {"value": away_summary["tendencyScore"], "sources": []},
            "r2": None,
            "zoneStats": {"average": away_summary["meanScore"], "count": reconstruction_count},
        },
        "trendComparisons": comparisons,
        "trendWinner": winner(),
        "requestedRank1": reconstruction_count,
        "requestedRank2": None,
        "rank1": reconstruction_count,
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
            "invalidReconstructionIssueCount": invalid_reconstruction_issue_count,
            "invalidReconstructionIssues": invalid_reconstruction_issues,
            "message": (
                f"⚠️ Scan partiel : {total_issue_count} match(s) utilisé(s) sans événements récupérés."
                if total_issue_count else
                (
                    f"⚠️ Reconstitution non valide ignorée/remplacée : {invalid_reconstruction_issue_count} match(s) à score non nul sans buts récupérables."
                    if invalid_reconstruction_issue_count else
                    "Scan complet : reconstitutions valides. Les matchs incomplets éventuels ont été ignorés et remplacés."
                )
            ),
        },
        "config": {
            "reconstructionCount": reconstruction_count,
            "trendCount": reconstruction_count,
            "trendMatchesNeeded": needed_matches,
            "pagesToLoad": PAGES_TO_LOAD,
            "system": "reconstruction",
            "trendLevelMode": level_mode,
            "trendToMeanEnabled": bool(trend_to_mean_enabled),
            "meanToTrendEnabled": bool(mean_to_trend_enabled),
            "varianceDirection": variance_direction,
            "varianceDirectionLabel": variance_direction_label,
            "reconstructionWindowBase": RECONSTRUCTION_WINDOW_BASE_MATCHES,
            "reconstructionWindowMax": RECONSTRUCTION_WINDOW_MAX_MATCHES,
            "reconstructionDirection": "newest_to_oldest",
            "displayDirection": "newest_to_oldest",
        },
    }

    update_scan_job(job_id, status="done", message="🧩 Scan reconstitutions terminé.", progress=100, result=result, finishedAt=now_ts())
    print(f"✅ Scan reconstitutions terminé: {job_id} · {reconstruction_count} reconstitutions · gagnant {result['trendWinner']['label']}")

def process_scan_job(job_id):
    raw = redis_cmd("GET", f"{SCAN_JOB_PREFIX}{job_id}")

    if not raw:
        print(f"Scan job absent: {job_id}")
        return

    job = json.loads(raw)
    status = str(job.get("status") or "").lower()

    if status in {"done", "error"}:
        print(f"Scan job ignoré car déjà terminé: {job_id} · statut={status}")
        return

    if status == "running" and job.get("workerClaimedAt"):
        print(f"Scan job ignoré car déjà pris par un worker: {job_id}")
        return

    params = job.get("params") or {}

    try:
        update_scan_job(
            job_id,
            status="running",
            message="Worker Termux connecté · préparation du scan…",
            progress=max(2, int(job.get("progress") or 0)),
            workerClaimedAt=now_ts(),
        )
    except Exception:
        pass

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
    print("Liaison scan: mode robuste v209 activé (pending set + file + latest + heartbeat).")
    print("Système tendance: curseur 1-100, extra configurable, limitation temps réglementaire configurable.")
    print("Événements: buts uniquement (But Avec Passeur, But Sans Passeur, CSC / Erreur). Cartons et passes seules ignorés.")
    print("Stabilité réseau: retry Web + matchs sans événements SofaScore signalés clairement.")
    print("Préchargement événements: désactivé par défaut pour économiser les requêtes.")
    print("Laisse cette fenêtre ouverte pendant que tu utilises l'app.")

    try:
        ping = redis_cmd("PING")
        print(f"Redis Upstash: OK ({ping})")
        send_worker_heartbeat(force=True)
        print("Heartbeat worker publié: OK")
    except Exception as e:
        print(f"❌ Redis Upstash inaccessible depuis Termux: {e}", file=sys.stderr)
        if once:
            return

    while True:
        value = None
        queue_key = None

        try:
            send_worker_heartbeat()
            # Priorité absolue au scan FOOTSCAN via mode robuste v209.
            value = pop_scan_job_fallback()
            queue_key = SCAN_QUEUE_KEY if value else None
        except RuntimeError as e:
            if is_upstash_quota_error(e):
                print("\n❌ Quota Upstash atteint: limite de requêtes dépassée.")
                print("Le worker ne peut plus lire la file tant que le quota n'est pas réinitialisé ou augmenté.")
                break
            raise

        if not value:
            try:
                # Anciennes files: on garde BRPOP avec un délai court.
                # Le scan principal n'en dépend plus.
                result = redis_cmd(
                    "BRPOP",
                    RAW_QUEUE_KEY,
                    RAW_PREFETCH_QUEUE_KEY,
                    "1" if once else "2",
                )
                queue_key, value = parse_brpop_result(result)
            except RuntimeError as e:
                if is_upstash_quota_error(e):
                    print("\n❌ Quota Upstash atteint: limite de requêtes dépassée.")
                    print("Le worker ne peut plus lire la file tant que le quota n'est pas réinitialisé ou augmenté.")
                    print("Solution: attendre le reset Upstash, passer l'instance en plan supérieur, ou changer de base Redis.")
                    break
                raise

        if not value:
            if once:
                print("Aucune requête en attente.")
                break
            global_idle_ts = now_ts()
            global LAST_IDLE_LOG_AT
            if global_idle_ts - LAST_IDLE_LOG_AT >= 30:
                print("Worker actif: aucun scan reçu pour l'instant.")
                LAST_IDLE_LOG_AT = global_idle_ts
            time.sleep(0.4)
            continue

        queue_key = normalize_queue_key(queue_key)

        if queue_key == SCAN_QUEUE_KEY or looks_like_scan_job_id(value):
            print(f"Scan job reçu: {value}")
            process_scan_job(value)
            continue

        if queue_key == RAW_QUEUE_KEY:
            process_raw_request(value)
            continue

        if queue_key == RAW_PREFETCH_QUEUE_KEY:
            process_prefetch_path(value)
            continue

        # Sécurité: si le provider renvoie un format inattendu, on ne perd
        # pas le contenu. Les IDs de scan sont traités plus haut; le reste
        # reste sur l'ancien flux brut.
        process_raw_request(value)


if __name__ == "__main__":
    main()
