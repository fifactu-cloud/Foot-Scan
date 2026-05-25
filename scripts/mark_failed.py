import os
import json
import urllib.request


def upstash(cmd):
    req = urllib.request.Request(
        os.environ['UPSTASH_REDIS_REST_URL'],
        data=json.dumps(cmd).encode('utf-8'),
        headers={
            'Authorization': f"Bearer {os.environ['UPSTASH_REDIS_REST_TOKEN']}",
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


job_key = f"job:{os.environ['JOB_ID']}"
current = upstash(['GET', job_key]).get('result')

if current:
    try:
        parsed = json.loads(current)
        if parsed.get('status') in ('error', 'done'):
            print(f"Job déjà en état terminal ({parsed.get('status')}), ne pas écraser")
            exit(0)
    except Exception:
        pass

payload = json.dumps({'status': 'error', 'error': 'Workflow a échoué avant que le script puisse rapporter'})
upstash(['SET', job_key, payload, 'EX', '3600'])
print("Marqué comme failed")
