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
curl -s http://127.0.0.1:8000/analyze -H 'Content-Type: application/json' -d '{"requestId":"Qwk449Um","minutes":1440}' | jq .
curl -s http://127.0.0.1:8000/analyze -H 'Content-Type: application/json' -d '{"text":"ERROR external API failed with status 502"}' | jq .
```

Docs: http://127.0.0.1:8000/docs

Keep port 8000 bound to localhost unless the service is protected. Set
`REQUEST_INVESTIGATION_TOKEN` to require the `X-Request-Investigation-Token`
header on `/requests/{request_id}`. The detailed response retains request
evidence with common password, token, secret, and authorization values redacted;
large application-log event messages are previews, with full redacted evidence
available in the detailed `timeline` field.

Loki range-query limit applies; a large result can be truncated. The current implementation does not paginate.

Set `API_TOKEN` to enable Groq analysis. The service sends only a compact,
redacted diagnostic context to `openai/gpt-oss-20b`; it does not alter the
existing request timeline or raw-log responses. Context defaults are capped at
40 events, 900 characters per event, and 12,000 total characters. Successful
request-ID analyses are cached by the fingerprint of that compact context;
send `"forceRefresh": true` to bypass the cache.

For `/analyze` request-ID investigations, the optional
`X-Request-Investigation-Token` header follows the same protection as the
request timeline endpoint. `minutes` defaults to 60 and is limited to 1-1440.
