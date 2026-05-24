import os
import json
import urllib.request

cmd = ['SET', f"job:{os.environ['JOB_ID']}",
       json.dumps({'status': 'error', 'error': 'Workflow exit inattendu'}),
       'EX', '3600']

req = urllib.request.Request(
    os.environ['UPSTASH_REDIS_REST_URL'],
    data=json.dumps(cmd).encode('utf-8'),
    headers={
        'Authorization': f"Bearer {os.environ['UPSTASH_REDIS_REST_TOKEN']}",
        'Content-Type': 'application/json',
    },
    method='POST',
)
urllib.request.urlopen(req, timeout=10).read()
