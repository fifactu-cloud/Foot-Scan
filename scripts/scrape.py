import os
import sys
import json
import time
import urllib.request
from playwright.sync_api import sync_playwright


UPSTASH_URL = os.environ["UPSTASH_REDIS_REST_URL"]
UPSTASH_TOKEN = os.environ["UPSTASH_REDIS_REST_TOKEN"]
JOB_ID = os.environ["JOB_ID"]
MATCH_ID = os.environ["MATCH_ID"]

SKIP_HOME = int(os.environ.get("SKIP_HOME", "0") or 0)
SKIP_AWAY = int(os.environ.get("SKIP_AWAY", "0") or 0)
MAX_NEEDED = int(os.environ.get("MAX_NEEDED", "6") or 6)

HEADLESS = os.environ.get("HEADLESS", "1") != "0"

STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
Object.defineProperty(navigator, 'languages', { get: () => ['fr-FR', 'fr', 'en'] });
window.chrome = { runtime: {}, app: {} };
"""


def upstash_cmd(*cmd):
    req = urllib.request.Request(
        UPSTASH_URL,
        data=json.dumps(list(cmd)).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {UPSTASH_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def write_job(payload):
    upstash_cmd("SET", f"job:{JOB_ID}", json.dumps(payload), "EX", "3600")


def count_useful(incidents):
    n = 0

    for inc in incidents:
        minute = inc.get("time")

        if minute is None or minute < 1 or minute > 90:
            continue

        incident_type = inc.get("incidentType")

        if incident_type == "goal":
            n += 1

            if inc.get("assist1"):
                n += 1

        elif incident_type == "card":
            player = inc.get("player") or {}
            incident_class = inc.get("incidentClass")

            if player.get("id") and incident_class in ("yellow", "yellowRed", "red"):
                n += 1

    return n


def parse_json_response(status, body, path, source):
    if not body:
        return None, f"{source}: réponse vide sur {path}"

    body = body.strip()

    if status != 200:
        return None, f"{source}: HTTP {status} sur {path}: {body[:300]}"

    if body.startswith("<"):
        return None, f"{source}: HTML reçu au lieu de JSON sur {path}: {body[:300]}"

    try:
        data = json.loads(body)
    except Exception:
        return None, f"{source}: JSON invalide sur {path}: {body[:300]}"

    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return None, f"{source}: erreur SofaScore sur {path}: {data['error']}"

    return data, None


def main():
    browser = None

    try:
        write_job({"status": "pending"})

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=HEADLESS,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                ],
            )

            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                locale="fr-FR",
                timezone_id="Europe/Paris",
                viewport={"width": 1366, "height": 768},
                extra_http_headers={
                    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                },
            )

            context.add_init_script(STEALTH_JS)

            page = context.new_page()

            target_url = f"https://www.sofascore.com/event/{MATCH_ID}"
            print(f"Visite de {target_url} ...")

            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(5000)
            except Exception as e:
                print(f"goto warning: {e}", file=sys.stderr)

            def fetch(path):
                clean_path = path.lstrip("/")
                last_error = None

                # Méthode 1 : fetch depuis la vraie page SofaScore déjà ouverte.
                for attempt in range(2):
                    try:
                        result = page.evaluate(
                            """
                            async (path) => {
                                try {
                                    const response = await fetch(`/api/v1/${path}`, {
                                        method: 'GET',
                                        credentials: 'include',
                                        cache: 'no-store',
                                        headers: {
                                            'Accept': 'application/json, text/plain, */*',
                                            'X-Requested-With': 'XMLHttpRequest'
                                        }
                                    });

                                    const text = await response.text();

                                    return {
                                        status: response.status,
                                        body: text
                                    };
                                } catch (e) {
                                    return {
                                        status: 0,
                                        body: 'JS error: ' + e.message
                                    };
                                }
                            }
                            """,
                            clean_path,
                        )

                        data, error = parse_json_response(
                            result.get("status", 0),
                            result.get("body", ""),
                            clean_path,
                            "page.fetch",
                        )

                        if data is not None:
                            return data

                        last_error = error
                        print(f"Tentative page.fetch échouée: {error}", file=sys.stderr)
                        page.wait_for_timeout(1500)

                    except Exception as e:
                        last_error = f"page.fetch exception: {type(e).__name__}: {e}"
                        print(last_error, file=sys.stderr)

                # Méthode 2 : ouvrir l’URL API dans un vrai onglet Chromium.
                urls = [
                    f"https://www.sofascore.com/api/v1/{clean_path}",
                    f"https://api.sofascore.com/api/v1/{clean_path}",
                ]

                for url in urls:
                    api_page = None

                    try:
                        api_page = context.new_page()
                        response = api_page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=45000,
                        )

                        api_page.wait_for_timeout(1000)

                        status = response.status if response else 0
                        body = api_page.locator("body").inner_text(timeout=8000)

                        data, error = parse_json_response(
                            status,
                            body,
                            clean_path,
                            f"browser.goto {url}",
                        )

                        if data is not None:
                            return data

                        last_error = error
                        print(f"Tentative browser.goto échouée: {error}", file=sys.stderr)

                    except Exception as e:
                        last_error = f"browser.goto exception: {type(e).__name__}: {e}"
                        print(last_error, file=sys.stderr)

                    finally:
                        if api_page:
                            try:
                                api_page.close()
                            except Exception:
                                pass

                raise RuntimeError(last_error or f"Fetch impossible sur {clean_path}")

            ev_data = fetch(f"event/{MATCH_ID}")
            event = ev_data.get("event", ev_data) if isinstance(ev_data, dict) else ev_data

            if (
                not isinstance(event, dict)
                or "homeTeam" not in event
                or "awayTeam" not in event
            ):
                raise RuntimeError(f"Format event inattendu: {str(ev_data)[:300]}")

            home = event["homeTeam"]
            away = event["awayTeam"]

            def scan_team(team_id, skip, max_needed):
                matches_used = []
                total = 0
                skipped = 0
                page_n = 0
                safety = 0

                while total < max_needed and safety < 8:
                    page_data = fetch(f"team/{team_id}/events/last/{page_n}")

                    if isinstance(page_data, dict):
                        events = page_data.get("events", [])
                    elif isinstance(page_data, list):
                        events = page_data
                    else:
                        events = []

                    finished = [
                        match
                        for match in events
                        if (match.get("status") or {}).get("type") == "finished"
                    ]

                    if not finished:
                        break

                    for match in finished:
                        if skipped < skip:
                            skipped += 1
                            continue

                        if total >= max_needed:
                            break

                        match_id = match.get("id")

                        if not match_id:
                            continue

                        inc_data = fetch(f"event/{match_id}/incidents")

                        if isinstance(inc_data, dict):
                            incidents = inc_data.get("incidents", [])
                        elif isinstance(inc_data, list):
                            incidents = inc_data
                        else:
                            incidents = []

                        home_name = (match.get("homeTeam") or {}).get("name", "?")
                        away_name = (match.get("awayTeam") or {}).get("name", "?")
                        home_score = (match.get("homeScore") or {}).get("current", "-")
                        away_score = (match.get("awayScore") or {}).get("current", "-")

                        matches_used.append(
                            {
                                "label": (
                                    f"{home_name} {home_score}-{away_score} "
                                    f"{away_name}"
                                ),
                                "id": match_id,
                                "incidents": incidents,
                            }
                        )

                        total += count_useful(incidents)

                    page_n += 1
                    safety += 1

                return matches_used

            print(f"Scan home: {home.get('name')} / team {home['id']} ...")
            home_matches = scan_team(home["id"], SKIP_HOME, MAX_NEEDED)

            print(f"Scan away: {away.get('name')} / team {away['id']} ...")
            away_matches = scan_team(away["id"], SKIP_AWAY, MAX_NEEDED)

            result = {
                "status": "done",
                "data": {
                    "event": {
                        "homeTeam": {
                            "id": home["id"],
                            "name": home.get("name", "?"),
                        },
                        "awayTeam": {
                            "id": away["id"],
                            "name": away.get("name", "?"),
                        },
                    },
                    "home": {
                        "matchesUsed": home_matches,
                    },
                    "away": {
                        "matchesUsed": away_matches,
                    },
                },
            }

            write_job(result)

            print(
                f"OK: home={len(home_matches)} matches, "
                f"away={len(away_matches)} matches"
            )

            browser.close()

    except Exception as e:
        try:
            write_job({"status": "error", "error": str(e)})
        except Exception as write_error:
            print(f"ERREUR Upstash: {write_error}", file=sys.stderr)

        print(f"ERREUR: {e}", file=sys.stderr)

        if browser:
            try:
                browser.close()
            except Exception:
                pass

        sys.exit(1)


if __name__ == "__main__":
    main()
