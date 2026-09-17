#!/usr/bin/env python3
"""hermes_dumbscope.py — read-only DUMBscope-client (fase 4).

Verantwoordelijkheden: health, sessie-auth (login bij 401), incidents ophalen
(actief + recent resolved), normaliseren naar Hermes-intern formaat, metingen.
Geen LLM, geen Telegram, geen remediation, geen write-routes (uitsluitend GET
en de login-POST; /api/actions wordt nooit aangeroepen).

Auth: sessie-cookie (dumbscope_session, TTL 7 dagen bij DUMBscope). Wachtwoord
uit bestaande secretlocatie (geen duplicatie):
  1. $HERMES_HOME/secrets/dumbscope-admin-password.txt  (voorkeur)
  2. $HERMES_HOME/secrets/arrsight-admin-password.txt   (fallback, bestaand)
Sessie-token wordt bewaard in secrets/dumbscope-session (0600, uid 10000) —
een credential hoort niet in de state-database of eventlog.
"""
import json, time, urllib.error, urllib.request
from pathlib import Path

SESSION_FILE = "dumbscope-session"
PW_FILES = ("dumbscope-admin-password.txt", "arrsight-admin-password.txt")


class DumbScopeError(Exception):
    def __init__(self, reason, status=None, detail=""):
        super().__init__(f"{reason}" + (f" ({status})" if status else "") + (f": {detail}" if detail else ""))
        self.reason = reason
        self.status = status


SEV_MAP = {"info": "notice", "warning": "warning", "critical": "critical"}


def map_severity(sev):
    """Expliciete deterministic mapping; onbekend -> notice + gemarkeerd."""
    if sev in SEV_MAP:
        return SEV_MAP[sev], False
    return "notice", True


def _iso(ms):
    if not ms:
        return None
    return datetime_iso(ms / 1000)


def datetime_iso(seconds):
    import datetime as dt
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat(timespec="seconds")


class DumbScopeClient:
    def __init__(self, base_url="http://192.168.1.2:8091", username="remco",
                 secrets_dir=None, timeout=15):
        self.base = base_url.rstrip("/")
        self.username = username
        self.secrets = Path(secrets_dir) if secrets_dir else Path("/tmp")
        self.timeout = timeout

    # ---------------------------------------------------------- primitives --
    def _request(self, path, *, method="GET", body=None, cookie=None, origin=False):
        headers = {"Accept": "application/json",
                   "User-Agent": "hermes-evaluator/1 (read-only)"}
        if origin:
            # DUMBscope weigert non-GET zonder same-origin header (CSRF-check)
            headers["Origin"] = self.base
        req = urllib.request.Request(self.base + path, method=method, headers=headers)
        if cookie:
            # _login geeft de kale token-waarde terug; maak er een volledige
            # cookie-header van (anders 401 op iedere GET na login).
            # Let op: cookienaam is dumbscope_session (underscore), het
            # sessie-BESTAND heet dumbscope-session (streepje).
            if "=" not in cookie:
                cookie = f"dumbscope_session={cookie}"
            req.add_header("Cookie", cookie)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, data=data, timeout=self.timeout) as r:
                payload = r.read()
                set_cookie = r.headers.get("Set-Cookie", "")
                code = r.status
        except urllib.error.HTTPError as e:
            # HTTP-code laten interpreteren door de caller (401 -> auth, etc.)
            e.read()
            return b"", e.headers.get("Set-Cookie", ""), e.code, time.monotonic() - t0
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise DumbScopeError("unavailable", None, str(e)[:120]) from None
        return payload, set_cookie, code, time.monotonic() - t0

    # ---------------------------------------------------------------- auth --
    def _password(self):
        for name in PW_FILES:
            p = self.secrets / name
            if p.exists():
                pw = p.read_text().strip()
                if pw:
                    return pw
        return None

    def _load_session(self):
        p = self.secrets / SESSION_FILE
        if p.exists():
            tok = p.read_text().strip()
            return tok or None
        return None

    def _save_session(self, token):
        p = self.secrets / SESSION_FILE
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(token + "\n")
        try:
            p.chmod(0o600)
        except OSError:
            pass

    def _login(self):
        pw = self._password()
        if not pw:
            raise DumbScopeError("auth_missing", None,
                                 f"geen wachtwoordbestand in {self.secrets}")
        try:
            payload, set_cookie, code, _ = self._request(
                "/api/auth/login", method="POST", origin=True,
                body={"username": self.username, "password": pw})
        except DumbScopeError as e:
            if e.status in (401, 403):
                raise DumbScopeError("auth_invalid", e.status, "login geweigerd") from None
            raise
        if code in (401, 403):
            raise DumbScopeError("auth_invalid", code, "login geweigerd")
        if code != 200:
            raise DumbScopeError("http_error", code, "login mislukt")
        for part in set_cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "dumbscope_session" and v:
                self._save_session(v)
                return v
        raise DumbScopeError("http_error", code, "geen sessie-cookie in login-antwoord")

    # ----------------------------------------------------------------- api --
    def health(self):
        """Publiek endpoint; geeft (dict, bytes, seconden)."""
        payload, _, _, secs = self._request("/api/health")
        return json.loads(payload), len(payload), secs

    def _get_json(self, path, cookie):
        payload, _, code, secs = self._request(path, cookie=cookie)
        if code in (401, 403):
            raise DumbScopeError("auth_required", code, path)
        if code != 200:
            raise DumbScopeError("http_error", code, path)
        return json.loads(payload), len(payload), secs

    def poll(self, active_limit=200, resolved_limit=20):
        """Health + incident-delta. Geeft structuur met metingen; auth wordt
        maximaal één keer vernieuwd bij 401. Wijst DumbScopeError voor
        unavailable/auth_missing/auth_invalid."""
        h, hbytes, hsecs = self.health()
        if not isinstance(h, dict) or h.get("status") != "ok":
            raise DumbScopeError("degraded", None, f"health status={h.get('status')!r}")
        cookie = self._load_session()
        try:
            active, a_bytes, a_secs = self._get_json(f"/api/incidents?status=active&limit={active_limit}", cookie)
        except DumbScopeError as e:
            if e.reason != "auth_required":
                raise
            cookie = self._login()
            active, a_bytes, a_secs = self._get_json(f"/api/incidents?status=active&limit={active_limit}", cookie)
        try:
            resolved, r_bytes, r_secs = self._get_json(f"/api/incidents?status=resolved&limit={resolved_limit}", cookie)
        except DumbScopeError as e:
            if e.reason != "auth_required":
                raise
            cookie = self._login()
            resolved, r_bytes, r_secs = self._get_json(f"/api/incidents?status=resolved&limit={resolved_limit}", cookie)
        incidents = [normalize_incident(x) for x in active.get("incidents", [])]
        incidents += [normalize_incident(x) for x in resolved.get("incidents", [])
                      if x.get("status") == "resolved"]
        return {"ok": True, "health": h,
                "incidents": incidents,
                "metrics": {"active_count": active.get("incidents") and len(active["incidents"]),
                            "resolved_fetched": len(resolved.get("incidents", [])),
                            "payload_bytes": hbytes + a_bytes + r_bytes,
                            "runtime_s": round(hsecs + a_secs + r_secs, 2)}}

# ------------------------------------------------------------ normalisatie --
def normalize_incident(raw):
    sev, unmapped = map_severity(raw.get("severity"))
    ev = []
    for e in (raw.get("evidence") or [])[:10]:
        msg = e.get("message") if isinstance(e, dict) else str(e)
        if msg:
            ev.append(str(msg)[:240])
    return {
        "source": "dumbscope",
        "fingerprint": f"dumbscope:{raw.get('fingerprint')}",
        "source_fingerprint": raw.get("fingerprint"),
        "severity": sev,
        "severity_source": raw.get("severity"),
        "severity_unmapped": unmapped,
        "state": "resolved" if raw.get("status") == "resolved" else "active",
        "source_status": raw.get("status"),
        "title": (raw.get("title") or "")[:200],
        "summary": (raw.get("summary") or "")[:500] or None,
        "root_cause_service": raw.get("rootCauseService"),
        "affected_services": raw.get("affectedServices") or [],
        "first_seen_ms": raw.get("firstSeen"),
        "last_seen_ms": raw.get("lastSeen"),
        "resolved_at_ms": raw.get("resolvedAt"),
        "first_seen": _iso(raw.get("firstSeen")),
        "last_seen": _iso(raw.get("lastSeen")),
        "resolved_at": _iso(raw.get("resolvedAt")),
        "occurrences": int(raw.get("occurrences") or 0),
        "evidence": ev,
        "source_incident_id": raw.get("id"),
    }
