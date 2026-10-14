import json
import hmac
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import quote
import httpx
from fastapi import FastAPI, Header, HTTPException, Query
app = FastAPI(title="UAT Log Investigator", version="0.1.0")
LOKI_URL = os.getenv("LOKI_URL", "http://127.0.0.1:13100").rstrip("/")
REQUEST_INVESTIGATION_TOKEN = os.getenv("REQUEST_INVESTIGATION_TOKEN")
SELECTOR = '{env="uat",app="uat"}'
HEADER = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) "
    r"\[(?P<thread>[^]]+)\] (?P<level>TRACE|DEBUG|INFO|WARN|ERROR)\s+"
    r"\[(?P<request_id>[^,\]]*),(?P<user>[^\]]*)\] "
    r"\[(?P<pid>[^]]+)\] --- (?P<logger>.*?) : (?P<message>[\s\S]*)$"
)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
EXCEPTION = re.compile(r"\b([\w.$]+(?:Exception|Error))\b")
EMAIL_DOMAIN = "@dcbindia.com"
AUTHORIZATION_VALUE = re.compile(r"(?i)(\bauthorization\s*[:=]\s*)(?:bearer|basic)\s+\S+")
SENSITIVE_FIELD = re.compile(
    r'''(?i)(?P<prefix>["']?(?:password|passwd|pwd|access[_-]?token|refresh[_-]?token|'''
    r'''id[_-]?token|client[_-]?secret|api[_-]?key|authorization|secret|mobileNo|primaryMobileNumber|phone|email|panNumber|aadhaarVaultNumber|externalAadhaarRefNo|applicantExternalAadhaarRefNo|beneficiaryBankAccountNo|bankAccountNumber|accountNumber|beneficiaryIfscCode)["']?\s*[:=]\s*)'''
    r'''(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}]+)'''
)
def redact_sensitive_text(value: str) -> str:
    value = AUTHORIZATION_VALUE.sub(r"\1[REDACTED]", value)
    def redact_field(match: re.Match) -> str:
        original = match.group("value")
        if original.startswith('"') and original.endswith('"'):
            replacement = '"[REDACTED]"'
        elif original.startswith("'") and original.endswith("'"):
            replacement = "'[REDACTED]'"
        else:
            replacement = "[REDACTED]"
        return match.group("prefix") + replacement
    return SENSITIVE_FIELD.sub(redact_field, value)
def redact_request_entry(entry: dict) -> dict:
    redacted = dict(entry)
    for field in ("raw", "message"):
        if isinstance(redacted.get(field), str):
            redacted[field] = redact_sensitive_text(redacted[field])
    return redacted
def authorize_request_investigation(token: str | None) -> None:
    if REQUEST_INVESTIGATION_TOKEN and (
        not token or not hmac.compare_digest(token, REQUEST_INVESTIGATION_TOKEN)
    ):
        raise HTTPException(status_code=401, detail="Request investigation access denied")
# Match an exception declaration at the beginning of a line, not a casual
# mention of an exception in an ordinary INFO log.
EXCEPTION_DECLARATION = re.compile(
    r"(?m)^\s*(?:Caused by:\s*|Suppressed:\s*)?"
    r"(?P<class>[\w.$]+(?:Exception|Error))"
    r"(?::\s*(?P<message>[^\r\n]*))?\s*$"
)
ADVICE_EXCEPTION_DECLARATION = re.compile(
    r"(?m)^\s*GlobalExceptionHandlingControllerAdvice\b[^\r\n]*?"
    r"(?P<class>[\w.$]+(?:Exception|Error))\s*:\s*(?P<message>[^\r\n]*)"
)

def find_exception_declaration(message: str):
    return EXCEPTION_DECLARATION.search(message) or ADVICE_EXCEPTION_DECLARATION.search(message)

def parse_entry(ns: str, raw: str) -> dict:
    cleaned = ANSI.sub("", raw)
    match = HEADER.match(cleaned)
    entry = {"timestamp": datetime.fromtimestamp(int(ns) / 1e9, timezone.utc).isoformat(),
             "raw": cleaned}
    if match:
        entry.update(match.groupdict())
        entry["applicationTimestamp"] = entry.pop("timestamp")
        entry["timestamp"] = datetime.fromtimestamp(int(ns) / 1e9, timezone.utc).isoformat()
        entry["message"] = match.group("message")
    else:
        entry.update({"level": None, "request_id": None, "user": None, "logger": None, "thread": None,
                      "message": cleaned})
    declaration = find_exception_declaration(entry["message"])
    entry["exception"] = declaration.group("class") if declaration else None
    return entry
def normalize_username(username: str) -> str:
    normalized = username.strip().casefold()
    if normalized.endswith(EMAIL_DOMAIN):
        normalized = normalized[:-len(EMAIL_DOMAIN)]
    return normalized
def is_anonymous_username(username: str | None) -> bool:
    return not username or normalize_username(username) in {
        "anonymous", "anonymoususer", "anonymous_user", "anonymous-user", "unknown", "n/a"
    }
def classify_error(entry: dict, request_url: str | None) -> str:
    logger = (entry.get("logger") or "").casefold()
    exception = (entry.get("exception") or "").casefold()
    endpoint = (request_url or "").casefold()
    auth_logger = re.search(r"auth|security|identity|credential", logger)
    auth_exception = re.search(
        r"authentication|authorization|accessdenied|badcredentials|credential|"
        r"invalidtoken|jwt|oauth|tokenexpired|usernamenotfound|accountlocked|accountdisabled",
        exception,
    )
    auth_endpoint = re.search(
        r"/(?:auth|login|logout|oauth|token|session|sso|signin|signout)(?:/|\?|$)", endpoint
    )
    return "authentication" if auth_logger or auth_exception or auth_endpoint else "application"
def enrich_recent_errors(errors: list[dict], related_entries: list[dict], minutes: int) -> list[dict]:
    related_by_id = {}
    for entry in related_entries:
        if entry["request_id"]:
            related_by_id.setdefault(entry["request_id"], []).append(entry)
    enriched = []
    for error in errors:
        request_id = error["request_id"]
        related = related_by_id.get(request_id, [])
        user = None if is_anonymous_username(error["user"]) else normalize_username(error["user"])
        if user is None:
            correlated_users = {normalize_username(entry["user"]) for entry in related
                                if not is_anonymous_username(entry["user"])}
            if len(correlated_users) == 1:
                user = correlated_users.pop()
        request_url = None
        request_events = sorted(related, key=lambda entry: entry["timestamp"])
        for marker in ("START", "END"):
            for event in request_events:
                fields = parse_request_fields(event, marker)
                if fields and fields["uri"]:
                    request_url = fields["uri"]
                    break
            if request_url:
                break
        if user:
            activity_url = f"/users/{quote(user, safe='')}/activity?minutes={minutes}"
        elif request_id:
            activity_url = f"/requests/{quote(request_id, safe='')}"
        else:
            activity_url = None
        item = dict(error)
        item.update({"user": user, "requestId": request_id,
                     "category": classify_error(error, request_url),
                     "requestUrl": request_url, "activityUrl": activity_url})
        enriched.append(item)
    return enriched
def parse_request_fields(entry: dict, marker: str) -> dict | None:
    match = re.search(rf"\bREQ {marker}\s*\|(?P<fields>.*)", entry["message"])
    if not match:
        return None
    fields = {}
    segments = match.group("fields").split("|")
    for segment in segments:
        key, separator, value = segment.partition("=")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    result = {"method": fields.get("method"),
              "uri": fields.get("uri") or fields.get("path") or fields.get("url"),
              "status": None, "durationMs": None}
    if segments:
        positional = re.match(r"\s*([A-Za-z]+)\s+(\S+)", segments[0])
        if positional:
            result["method"] = result["method"] or positional.group(1)
            result["uri"] = result["uri"] or positional.group(2)
    status = fields.get("status") or fields.get("statuscode") or fields.get("httpstatus")
    if status and status.isdigit():
        result["status"] = int(status)
    duration = (fields.get("durationms") or fields.get("duration")
                or fields.get("elapsedms"))
    duration_match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(?:ms)?\s*", duration or "",
                                  re.IGNORECASE)
    if duration_match:
        value = float(duration_match.group(1))
        result["durationMs"] = int(value) if value.is_integer() else value
    return result
def _timestamp_key(timestamp: str) -> datetime:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed
def build_user_activity(entries: list[dict], username: str, limit: int) -> dict:
    normalized_username = normalize_username(username)
    matching = [entry for entry in entries
                if entry["user"] and normalize_username(entry["user"]) == normalized_username]
    matching.sort(key=lambda entry: _timestamp_key(entry["timestamp"]))
    grouped = {}
    for entry in matching:
        request_id = entry["request_id"]
        if request_id:
            grouped.setdefault(request_id, []).append(entry)
    requests = []
    endpoint_counts = Counter()
    durations = []
    failed_requests = 0
    completed_requests = 0
    for request_id, request_entries in grouped.items():
        starts = [(entry, parse_request_fields(entry, "START")) for entry in request_entries]
        starts = [(entry, fields) for entry, fields in starts if fields is not None]
        ends = [(entry, parse_request_fields(entry, "END")) for entry in request_entries]
        ends = [(entry, fields) for entry, fields in ends if fields is not None]
        start_entry, start_fields = starts[0] if starts else (None, {})
        end_entry, end_fields = ends[-1] if ends else (None, {})
        errors = [entry for entry in request_entries
                  if entry["level"] == "ERROR" or entry["exception"]]
        timestamp = (start_entry or end_entry or request_entries[0])["timestamp"]
        method = start_fields.get("method") or end_fields.get("method")
        uri = start_fields.get("uri") or end_fields.get("uri")
        status = end_fields.get("status")
        duration = end_fields.get("durationMs")
        completed = end_entry is not None
        failed = bool(errors) or (status is not None and status >= 400)
        requests.append({"requestId": request_id, "timestamp": timestamp, "method": method,
                         "uri": uri, "status": status, "durationMs": duration,
                         "hasError": bool(errors), "errorCount": len(errors)})
        if completed:
            completed_requests += 1
        if failed:
            failed_requests += 1
        if duration is not None:
            durations.append(duration)
        if uri:
            endpoint_counts[(method, uri)] += 1
    requests.sort(key=lambda request: _timestamp_key(request["timestamp"]))
    top_endpoints = [{"method": method, "uri": uri, "count": count}
                     for (method, uri), count in sorted(
                         endpoint_counts.items(),
                         key=lambda item: (-item[1], item[0][1], item[0][0] or ""),
                     )[:10]]
    return {
        "username": normalized_username,
        "environment": "uat",
        "truncated_possible": len(entries) >= limit,
        "summary_is_exact": len(entries) < limit,
        "requests": requests,
        "summary": {
            "totalRequests": len(requests),
            "completedRequests": completed_requests,
            "failedRequests": failed_requests,
            "averageDurationMs": round(sum(durations) / len(durations), 2) if durations else None,
            "topEndpoints": top_endpoints,
        },
    }
async def loki_query(query: str, minutes: int, limit: int, direction: str = "BACKWARD",
                     window_end: datetime | None = None) -> list[dict]:
    end = window_end or datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    params = {"query": query, "start": str(int(start.timestamp() * 1_000_000_000)),
              "end": str(int(end.timestamp() * 1_000_000_000)), "limit": limit,
              "direction": direction}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"Loki query failed: {type(exc).__name__}") from exc
    if data.get("status") != "success":
        raise HTTPException(status_code=502, detail="Loki returned unsuccessful status")
    entries = [parse_entry(ns, line) for stream in data.get("data", {}).get("result", [])
               for ns, line in stream.get("values", [])]
    entries.sort(key=lambda x: x["timestamp"])
    return entries
@app.get("/health")
async def health():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{LOKI_URL}/ready")
            response.raise_for_status()
        return {"status": "ok", "loki": "ready", "environment": "uat"}
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Loki unavailable; check SSH tunnel")
def request_event(entry: dict, request_id: str, event_index: int) -> tuple[dict, dict | None]:
    message = entry["message"]
    start_fields = parse_request_fields(entry, "START")
    end_fields = parse_request_fields(entry, "END")
    if start_fields is not None:
        event_type = "REQUEST_START"
    elif end_fields is not None:
        event_type = "REQUEST_END"
    elif entry["exception"]:
        event_type = "EXCEPTION"
    else:
        event_type = "APPLICATION_LOG"
    exception = None
    exception_match = find_exception_declaration(message)
    if entry["exception"]:
        exception_class = exception_match.group("class") if exception_match else entry["exception"]
        exception_message = exception_match.group("message").strip() if exception_match and exception_match.group("message") else None
        exception = {
            "eventId": f"event-{event_index}",
            "timestamp": entry["timestamp"],
            "requestId": request_id if entry["request_id"] == request_id else None,
            "exceptionClass": exception_class,
            "message": exception_message,
            "stackTrace": message,
        }
    event_message = message.splitlines()[0] if entry["exception"] else message
    truncated = event_type == "APPLICATION_LOG" and len(event_message) > 300
    if truncated:
        event_message = event_message[:297] + "..."
    event = {
        "eventId": f"event-{event_index}",
        "timestamp": entry["timestamp"],
        "level": entry["level"],
        "logger": entry["logger"],
        "thread": entry["thread"],
        "eventType": event_type,
        "message": event_message,
        "raw": entry["raw"],
        "truncated": truncated,
        "requestId": request_id if entry["request_id"] == request_id else None,
    }
    if exception:
        event["exceptionId"] = exception["eventId"]
    return event, exception
def request_marker_metadata(entry: dict, marker: str) -> dict:
    fields = parse_request_fields(entry, marker) or {}
    match = re.search(rf"\bREQ {marker}\s*\|(?P<fields>.*)", entry["message"])
    parsed = {}
    if match:
        for segment in match.group("fields").split("|"):
            key, separator, value = segment.partition("=")
            if separator:
                parsed[key.strip().casefold().replace("_", "")] = value.strip()
    fields.update({
        "platform": parsed.get("platform"),
        "appVersion": parsed.get("appversion"),
        "clientOs": parsed.get("clientos") or parsed.get("os"),
    })
    return fields
def build_request_investigation(request_id: str, entries: list[dict], minutes: int,
                                limit: int, window_start: datetime,
                                window_end: datetime, loki_entry_count: int) -> dict:
    starts = [(entry, request_marker_metadata(entry, "START")) for entry in entries
              if parse_request_fields(entry, "START") is not None]
    ends = [(entry, request_marker_metadata(entry, "END")) for entry in entries
            if parse_request_fields(entry, "END") is not None]
    start_entry, start_fields = starts[0] if starts else (None, {})
    end_entry, end_fields = ends[-1] if ends else (None, {})
    users = [entry["user"].strip() for entry in entries
             if entry["user"] and not is_anonymous_username(entry["user"])]
    user = None
    if start_entry and start_entry["user"] and not is_anonymous_username(start_entry["user"]):
        user = start_entry["user"].strip()
    elif len(set(users)) == 1:
        user = users[0]
    events = []
    exceptions = []
    for index, entry in enumerate(entries, 1):
        event, exception = request_event(entry, request_id, index)
        events.append(event)
        if exception:
            exceptions.append(exception)
    request = {
        "requestId": request_id,
        "user": user,
        "method": start_fields.get("method") or end_fields.get("method"),
        "uri": redact_sensitive_text(start_fields.get("uri") or end_fields.get("uri")) if (start_fields.get("uri") or end_fields.get("uri")) else None,
        "startedAt": start_entry["timestamp"] if start_entry else None,
        "endedAt": end_entry["timestamp"] if end_entry else None,
        "status": end_fields.get("status"),
        "durationMs": end_fields.get("durationMs"),
        "platform": start_fields.get("platform") or end_fields.get("platform"),
        "appVersion": start_fields.get("appVersion") or end_fields.get("appVersion"),
        "clientOs": start_fields.get("clientOs") or end_fields.get("clientOs"),
    }
    truncated = loki_entry_count >= limit
    return {
        "request": request,
        "events": events,
        "exceptions": exceptions,
        "query": {
            "windowStart": window_start.isoformat(),
            "windowEnd": window_end.isoformat(),
            "minutes": minutes,
            "returnedEntries": len(entries),
            "truncatedPossible": truncated,
        },
    }
def request_entry_matches(entry: dict, request_id: str) -> bool:
    if entry["request_id"] == request_id:
        return True
    malformed_header = re.match(
        r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} \[[^]]+\] \S+\s+"
        r"\[(?P<request_id>[^,\]]+),",
        entry["raw"],
    )
    return bool(malformed_header and malformed_header.group("request_id") == request_id)
@app.get("/requests/{request_id}")
async def request_timeline(
    request_id: str,
    minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    access_token: Annotated[str | None, Header(alias="X-Request-Investigation-Token")] = None,
):
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,64}", request_id):
        raise HTTPException(status_code=400, detail="Invalid request ID")
    authorize_request_investigation(access_token)
    # Match MDC field rather than arbitrary message occurrences.
    query = SELECTOR + f' |= "[{request_id},"'
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(minutes=minutes)
    loki_entries = await loki_query(query, minutes, limit, window_end=window_end)
    entries = [redact_request_entry(e) for e in loki_entries
               if request_entry_matches(e, request_id)]
    starts = [e for e in entries if "REQ START |" in e["message"]]
    ends = [e for e in entries if "REQ END |" in e["message"]]
    structured = build_request_investigation(
        request_id, entries, minutes, limit, window_start, window_end, len(loki_entries)
    )
    return {"request_id": request_id, "environment": "uat", "count": len(entries),
            "truncated_possible": len(loki_entries) >= limit,
            "start": starts[0] if starts else None,
            "end": ends[-1] if ends else None,
            "errors": [e for e in entries if e["level"] == "ERROR"],
            "timeline": entries, **structured}
@app.get("/users/{user}/activity")
async def user_activity(
    user: str,
    minutes: Annotated[int, Query(ge=1, le=1440)] = 15,
    limit: Annotated[int, Query(ge=1, le=5000)] = 100,
):
    normalized_username = normalize_username(user)
    if not normalized_username:
        raise HTTPException(status_code=400, detail="Username must not be empty")
    mdc_pattern = (rf"(?i)\[[^,\]]+,\s*{re.escape(normalized_username)}"
                   rf"({re.escape(EMAIL_DOMAIN)})?\s*\]")
    query = SELECTOR + " |~ " + json.dumps(mdc_pattern)
    entries = await loki_query(query, minutes, limit)
    return build_user_activity(entries, normalized_username, limit)
@app.get("/errors/recent")
async def recent_errors(
    minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    exclude_anonymous: Annotated[bool, Query(alias="excludeAnonymous")] = False,
    exclude_auth: Annotated[bool, Query(alias="excludeAuth")] = False,
    user: str | None = None,
    exception: str | None = None,
):
    entries = await loki_query(SELECTOR + ' |= "ERROR"', minutes, limit)
    errors = [e for e in entries if e["level"] == "ERROR"]
    request_ids = list(dict.fromkeys(e["request_id"] for e in errors if e["request_id"]))
    related_entries = []
    if request_ids:
        request_pattern = r"\[(" + "|".join(re.escape(request_id) for request_id in request_ids) + r"),"
        related_entries = await loki_query(
            SELECTOR + " |~ " + json.dumps(request_pattern), minutes, limit
        )
    enriched = enrich_recent_errors(errors, related_entries, minutes)
    normalized_filter_user = normalize_username(user) if user else None
    normalized_filter_exception = exception.strip().casefold() if exception else None
    if normalized_filter_user:
        enriched = [error for error in enriched if error["user"] == normalized_filter_user]
    if normalized_filter_exception:
        enriched = [error for error in enriched if error["exception"] and
                    (error["exception"].casefold() == normalized_filter_exception or
                     error["exception"].rsplit(".", 1)[-1].casefold() == normalized_filter_exception)]
    if exclude_anonymous:
        enriched = [error for error in enriched if error["user"] is not None]
    if exclude_auth:
        enriched = [error for error in enriched if error["category"] != "authentication"]
    truncated_possible = len(entries) >= limit or len(related_entries) >= limit
    enriched.reverse()
    return {"environment": "uat", "count": len(enriched),
            "truncated_possible": truncated_possible,
            "count_is_exact": not truncated_possible, "errors": enriched}
