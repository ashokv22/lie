# UAT Log Investigator

Read-only FastAPI prototype querying existing Loki logs through an SSH tunnel.

## Run in Ubuntu WSL

Terminal 1:

```bash
ssh -N -L 13100:127.0.0.1:3100 dev
```

Terminal 2:

```bash
cd uat-investigator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Try:

```bash
curl -s http://127.0.0.1:8000/health | jq .
curl -s 'http://127.0.0.1:8000/requests/39c1Yjae?minutes=1440' | jq '{request_id,count,start:(.start.message),end:(.end.message),errors:[.errors[].message]}'
curl -s 'http://127.0.0.1:8000/errors/recent?minutes=60&limit=20' | jq '{count,errors:[.errors[]|{timestamp,request_id,exception,message:(.message|split("\n")[0])}]}'
```

Docs: http://127.0.0.1:8000/docs

Keep port 8000 bound to localhost unless the service is protected. Set
`REQUEST_INVESTIGATION_TOKEN` to require the `X-Request-Investigation-Token`
header on `/requests/{request_id}`. The detailed response retains request
evidence with common password, token, secret, and authorization values redacted;
large application-log event messages are previews, with full redacted evidence
available in the detailed `timeline` field.

Loki range-query limit applies; a large result can be truncated. The current implementation does not paginate.
