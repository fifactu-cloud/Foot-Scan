import os
import sys
import json
import time
import urllib.request
from playwright.sync_api import sync_playwright

UPSTASH_URL = os.environ['UPSTASH_REDIS_REST_URL']
UPSTASH_TOKEN = os.environ['UPSTASH_REDIS_REST_TOKEN']
JOB_ID = os.environ['JOB_ID']
MATCH_ID = os.environ['MATCH_ID']
SKIP_HOME = int(os.environ.get('SKIP_HOME', '0') or 0)
SKIP_AWAY = int(os.environ.get('SKIP_AWAY', '0') or 0)
MAX_NEEDED = int(os.environ.get('MAX_NEEDED', '6') or 6)


STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'languages', {get: () => ['fr-FR', 'fr', 'en']});
window.chrome = {runtime: {}, app: {}};
"""


def upstash_cmd(*cmd):
    req = urllib.request.Request(
        UPSTASH_URL,
        data=json.dumps(list(cmd)).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {UPSTASH_TOKEN}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def write_job(payload):
    upstash_cmd('SET', f'job:{JOB_ID}', json.dumps(payload), 'EX', '3600')


def count_useful(incidents):
    n = 0
    for inc in incidents:
        m = inc.get('time')
        if m is None or m > 90 or m < 1:
            continue
        t = inc.get('incidentType')
        if t == 'goal':
            n += 1
            if inc.get('assist1'):
                n += 1
        elif t == 'card':
            if (inc.get('player') or {}).get('id'):
                cls = inc.get('incidentClass')
                if cls in ('yellow', 'yellowRed', 'red'):
                    n += 1
    return n


def main():
    try:
        write_job({'status': 'pending'})

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                ],
            )
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                locale='fr-FR',
                viewport={'width': 1366, 'height': 768},
                extra_http_headers={'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8'},
            )
            context.add_init_script(STEALTH_JS)

            page = context.new_page()
            target_url = f'https://www.sofascore.com/event/{MATCH_ID}'
            print(f"Visite de {target_url} ...")
            try:
                page.goto(target_url, wait_until='domcontentloaded', timeout=30000)
            except Exception as e:
                print(f"goto warning: {e}", file=sys.stderr)
            time.sleep(4)

            def fetch(path):
                url = f'https://api.sofascore.com/api/v1/{path}'
                result = page.evaluate("""
                    async (url) => {
                        try {
                            const r = await fetch(url, {
                                headers: {'Accept': 'application/json'},
                                credentials: 'include',
                            });
                            const text = await r.text();
                            return {status: r.status, body: text};
                        } catch (e) {
                            return {status: 0, body: 'JS error: ' + e.message};
                        }
                    }
                """, url)
                if result['status'] != 200:
                    raise RuntimeError(f"HTTP {result['status']} sur {path}: {result['body'][:300]}")
                try:
                    data = json.loads(result['body'])
                except Exception:
                    raise RuntimeError(f"Non-JSON sur {path}: {result['body'][:300]}")
                if isinstance(data, dict) and isinstance(data.get('error'), dict):
                    raise RuntimeError(f"Sofascore challenge sur {path}: {data['error']}")
                return data

            ev_data = fetch(f'event/{MATCH_ID}')
            event = ev_data.get('event', ev_data) if isinstance(ev_data, dict) else ev_data
            if not isinstance(event, dict) or 'homeTeam' not in event or 'awayTeam' not in event:
                raise RuntimeError(f"Format event inattendu: {str(ev_data)[:200]}")
            home = event['homeTeam']
            away = event['awayTeam']

            def scan_team(team_id, skip, max_needed):
                matches_used = []
                total = 0
                skipped = 0
                page_n = 0
                safety = 0
                while total < max_needed and safety < 6:
                    page_data = fetch(f'team/{team_id}/events/last/{page_n}')
                    if isinstance(page_data, dict):
                        evs = page_data.get('events', [])
                    elif isinstance(page_data, list):
                        evs = page_data
                    else:
                        evs = []
                    finished = [m for m in evs if (m.get('status') or {}).get('type') == 'finished']
                    if not finished:
                        break
                    for m in finished:
                        if skipped < skip:
                            skipped += 1
                            continue
                        if total >= max_needed:
                            break
                        inc_data = fetch(f"event/{m['id']}/incidents")
                        if isinstance(inc_data, dict):
                            incidents = inc_data.get('incidents', [])
                        elif isinstance(inc_data, list):
                            incidents = inc_data
                        else:
                            incidents = []
                        hn = (m.get('homeTeam') or {}).get('name', '?')
                        an = (m.get('awayTeam') or {}).get('name', '?')
                        hs = (m.get('homeScore') or {}).get('current', '-')
                        asc = (m.get('awayScore') or {}).get('current', '-')
                        matches_used.append({
                            'label': f"{hn} {hs}-{asc} {an}",
                            'id': m['id'],
                            'incidents': incidents,
                        })
                        total += count_useful(incidents)
                    page_n += 1
                    safety += 1
                return matches_used

            print(f"Scan home (team {home['id']})...")
            home_matches = scan_team(home['id'], SKIP_HOME, MAX_NEEDED)
            print(f"Scan away (team {away['id']})...")
            away_matches = scan_team(away['id'], SKIP_AWAY, MAX_NEEDED)

            browser.close()

        result = {
            'status': 'done',
            'data': {
                'event': {
                    'homeTeam': {'id': home['id'], 'name': home.get('name', '?')},
                    'awayTeam': {'id': away['id'], 'name': away.get('name', '?')},
                },
                'home': {'matchesUsed': home_matches},
                'away': {'matchesUsed': away_matches},
            },
        }
        write_job(result)
        print(f"OK: home={len(home_matches)} matches, away={len(away_matches)} matches")
    except Exception as e:
        write_job({'status': 'error', 'error': str(e)})
        print(f"ERREUR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
