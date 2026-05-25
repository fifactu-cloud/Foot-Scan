import os
import sys
import json
import time
import urllib.request
import urllib.error


QUEUE_KEY = "sofa:queue"
CACHE_PREFIX = "sofa:cache:"
ERROR_PREFIX = "sofa:error:"
REQUEST_PREFIX = "sofa:req:"
LOCK_PREFIX = "sofa:lock:"

CACHE_TTL_SECONDS = int(os.environ.get("SOFA_CACHE_TTL_SECONDS", "86400"))
ERROR_TTL_SECONDS = int(os.environ.get("SOFA_ERROR_TTL_SECONDS", "60"))
SLEEP_SECONDS = float(os.environ.get("WORKER_SLEEP_SECONDS", "1.5"))


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


def process_request(request_id):
    request_key = f"{REQUEST_PREFIX}{request_id}"
    raw = redis_cmd("GET", request_key)

    if not raw:
        print(f"Request expirée ou absente: {request_id}")
        return

    payload = json.loads(raw)
    path = payload["path"].lstrip("/")

    cache_key = f"{CACHE_PREFIX}{path}"
    error_key = f"{ERROR_PREFIX}{path}"
    lock_key = f"{LOCK_PREFIX}{request_id}"

    print(f"Traitement: {path}")

    try:
        body = sofa_fetch(path)

        redis_cmd("SET", cache_key, body, "EX", str(CACHE_TTL_SECONDS))
        redis_cmd("DEL", error_key)
        redis_cmd("DEL", request_key)
        redis_cmd("DEL", lock_key)

        print(f"OK: {path}")

    except Exception as e:
        error_payload = {
            "error": str(e),
            "path": path,
            "source": "local_worker",
        }

        redis_cmd("SET", error_key, json.dumps(error_payload), "EX", str(ERROR_TTL_SECONDS))
        redis_cmd("DEL", lock_key)

        print(f"ERREUR: {path}: {e}", file=sys.stderr)


def main():
    once = "--once" in sys.argv

    print("Foot/Scan worker local démarré.")
    print("Laisse cette fenêtre ouverte pendant que tu utilises l'app.")

    while True:
        request_id = redis_cmd("RPOP", QUEUE_KEY)

        if request_id:
            process_request(request_id)
        elif once:
            print("Aucune requête en attente.")
            break
        else:
            time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    main()
