import os
import sys
import json
import urllib.request
from curl_cffi import requests as cf_requests

UPSTASH_URL = os.environ['UPSTASH_REDIS_REST_URL']
UPSTASH_TOKEN = os.environ['UPSTASH_REDIS_REST_TOKEN']
JOB_ID = os.environ['JOB_ID']
MATCH_ID = os.environ['MATCH_ID']
SKIP_HOME = int(os.environ.get('SKIP_HOME', '0') or 0)
SKIP_AWAY = int(os.environ.get('SKIP_AWAY', '0') or 0)
MAX_NEEDED = int(os.environ.get('MAX_NEEDED', '6') or 6)

SOFA_BASE = 'https://api.sofascore.com/api/v1'


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


def fetch_sofa(path):
    url = f"{SOFA_BASE}/{path}"
    try:
        r = cf_requests.get(
            url,
            impersonate='chrome',
            headers={
                'Accept': 'application/json',
                'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
                'Referer': 'https://www.sofascore.com/',
                'Origin': 'https://www.sofascore.com',
            },
            timeout=20,
        )
    except Exception as e:
        raise RuntimeError(f"Réseau KO sur {path}: {e}")
    if r.status_code == 403:
        raise RuntimeError(f"Sofascore challenge 403 sur {path} (curl_cffi insuffisant)")
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} sur {path}: {r.text[:200]}")
    try:
        data = r.json()
    except Exception:
        raise RuntimeError(f"Réponse non-JSON sur {path}: {r.text[:200]}")
    if isinstance(data, dict) and isinstance(data.get('error'), dict):
        err = data['error']
        raise RuntimeError(f"Sofascore error sur {path}: {err}")
    return data


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


def scan_team(team_id, skip, max_needed):
    matches_used = []
    total = 0
    skipped = 0
    page = 0
    safety = 0
    while total < max_needed and safety < 6:
        page_data = fetch_sofa(f'team/{team_id}/events/last/{page}')
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
            inc_data = fetch_sofa(f"event/{m['id']}/incidents")
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
        page += 1
        safety += 1
    return matches_used


def main():
    try:
        write_job({'status': 'pending'})
        ev_data = fetch_sofa(f'event/{MATCH_ID}')
        event = ev_data.get('event', ev_data) if isinstance(ev_data, dict) else ev_data
        if not isinstance(event, dict) or 'homeTeam' not in event or 'awayTeam' not in event:
            raise RuntimeError(f"Format event inattendu: {str(ev_data)[:200]}")
        home = event['homeTeam']
        away = event['awayTeam']
        home_matches = scan_team(home['id'], SKIP_HOME, MAX_NEEDED)
        away_matches = scan_team(away['id'], SKIP_AWAY, MAX_NEEDED)
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
