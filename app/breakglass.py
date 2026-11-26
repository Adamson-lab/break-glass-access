"""Break-glass emergency access service. Stdlib only: runs anywhere Python 3.9+ does.
Controls: dual control, time-boxed one-time credentials, hash-chained append-only audit, mandatory post-use review."""
import hashlib, json, os, re, secrets, sqlite3, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UNIT = int(os.getenv("BG_UNIT_SECONDS", "60"))      # seconds per "minute" (tests shrink it)
MAX_MIN = int(os.getenv("BG_MAX_MINUTES", "60"))    # hard cap on any grant
USERS = json.loads(os.getenv("BG_USERS", json.dumps({  # replace with your IdP/OIDC in production
    "t-alice": {"name": "alice", "role": "requester"}, "t-bob": {"name": "bob", "role": "approver"},
    "t-carol": {"name": "carol", "role": "approver"},  "t-dave": {"name": "dave", "role": "auditor"}})))
LOCK, CON = threading.RLock(), None
SCHEMA = """
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, requester TEXT, resource TEXT, reason TEXT,
  ticket TEXT, minutes INT, state TEXT, approver TEXT, created REAL, decided REAL, expires REAL, token_hash TEXT,
  review TEXT DEFAULT 'NONE', reviewer TEXT, review_note TEXT);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, rid INT,
  detail TEXT, prev TEXT, hash TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
"""

def init(path=None):
    global CON
    CON = sqlite3.connect(path or os.getenv("BG_DB", "breakglass.db"), check_same_thread=False)
    CON.row_factory = sqlite3.Row
    CON.executescript(SCHEMA)

def _h(prev, ts, actor, action, rid, d):
    return hashlib.sha256(f"{prev}|{ts!r}|{actor}|{action}|{rid}|{d}".encode()).hexdigest()

def audit(actor, action, rid=None, detail=None):
    with LOCK:
        row = CON.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev, ts, d = (row["hash"] if row else "0" * 64), time.time(), json.dumps(detail or {}, sort_keys=True)
        CON.execute("INSERT INTO audit(ts,actor,action,rid,detail,prev,hash) VALUES(?,?,?,?,?,?,?)",
                    (ts, actor, action, rid, d, prev, _h(prev, ts, actor, action, rid, d)))
        CON.commit()
    print(json.dumps({"siem": "breakglass", "action": action, "actor": actor, "rid": rid}), flush=True)  # ship to SIEM/webhook

def verify():
    with LOCK:
        prev, n = "0" * 64, 0
        for r in CON.execute("SELECT * FROM audit ORDER BY seq"):
            if r["prev"] != prev or r["hash"] != _h(prev, r["ts"], r["actor"], r["action"], r["rid"], r["detail"]):
                return {"ok": False, "entries": n, "broken_at": r["seq"]}
            prev, n = r["hash"], n + 1
        return {"ok": True, "entries": n, "head": prev}

def sweep():
    with LOCK:
        for r in CON.execute("SELECT id FROM requests WHERE state='APPROVED' AND expires<?", (time.time(),)).fetchall():
            CON.execute("UPDATE requests SET state='EXPIRED', review='PENDING' WHERE id=?", (r["id"],))
            audit("system", "EXPIRE", r["id"])

def _row(r): d = dict(r); d.pop("token_hash", None); return d
def _get(rid): return CON.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()

# ---- handlers: (user, match, body, headers) -> (status, json) ----
def create(u, m, b, h):
    if u["role"] == "auditor": return 403, {"error": "auditors cannot request access"}
    mins = int(b.get("minutes", 0))
    if not (1 <= mins <= MAX_MIN): return 400, {"error": f"minutes must be 1..{MAX_MIN}"}
    if len(b.get("reason", "")) < 15: return 400, {"error": "reason must be >= 15 chars"}
    if not re.match(r"^[A-Z]+-\d+$", b.get("ticket", "")): return 400, {"error": "valid incident ticket required (e.g. INC-4521)"}
    with LOCK:
        cur = CON.execute("INSERT INTO requests(requester,resource,reason,ticket,minutes,state,created) VALUES(?,?,?,?,?,'PENDING',?)",
                          (u["name"], b["resource"], b["reason"], b["ticket"], mins, time.time())); CON.commit()
    audit(u["name"], "REQUEST", cur.lastrowid, {k: b[k] for k in ("resource", "ticket", "minutes")})
    return 201, {"id": cur.lastrowid, "state": "PENDING"}

def listing(u, m, b, h):
    q, a = ("SELECT * FROM requests ORDER BY id DESC", ()) if u["role"] != "requester" else \
           ("SELECT * FROM requests WHERE requester=? ORDER BY id DESC", (u["name"],))
    return 200, [_row(r) for r in CON.execute(q, a)]

def one(u, m, b, h):
    r = _get(m[0]); return (200, _row(r)) if r else (404, {"error": "not found"})

def action(u, m, b, h):
    rid, act = int(m[0]), m[1]
    with LOCK:
        r = _get(rid)
        if not r: return 404, {"error": "not found"}
        if act in ("approve", "deny"):
            if u["role"] != "approver": return 403, {"error": "approver role required"}
            if u["name"] == r["requester"]: audit(u["name"], "SELF_APPROVAL_BLOCKED", rid); return 403, {"error": "dual control: cannot decide own request"}
            if r["state"] != "PENDING": return 409, {"error": f"state is {r['state']}"}
            if act == "deny" and not b.get("note"): return 400, {"error": "note required"}
            st, exp = ("APPROVED", time.time() + r["minutes"] * UNIT) if act == "approve" else ("DENIED", None)
            CON.execute("UPDATE requests SET state=?, approver=?, decided=?, expires=? WHERE id=?", (st, u["name"], time.time(), exp, rid)); CON.commit()
            audit(u["name"], act.upper(), rid, {"note": b.get("note", "")}); return 200, {"state": st}
        if act == "checkout":  # credential is released exactly once, only to the requester
            if u["name"] != r["requester"]: return 403, {"error": "only requester may check out"}
            if r["state"] != "APPROVED" or r["token_hash"]: return 409, {"error": "not available (not approved, or already checked out)"}
            tok = f"bg_{rid}_{secrets.token_urlsafe(24)}"
            CON.execute("UPDATE requests SET token_hash=? WHERE id=?", (hashlib.sha256(tok.encode()).hexdigest(), rid)); CON.commit()
            audit(u["name"], "CHECKOUT", rid); return 200, {"token": tok, "expires": r["expires"]}
        if act == "revoke":
            if u["role"] not in ("approver", "auditor"): return 403, {"error": "forbidden"}
            if r["state"] != "APPROVED": return 409, {"error": f"state is {r['state']}"}
            CON.execute("UPDATE requests SET state='REVOKED', review='PENDING' WHERE id=?", (rid,)); CON.commit()
            audit(u["name"], "REVOKE", rid); return 200, {"state": "REVOKED"}
        if act == "review":  # post-incident review: the control that closes the loop
            if u["role"] != "auditor": return 403, {"error": "auditor role required"}
            if r["review"] != "PENDING": return 409, {"error": "no review pending"}
            if b.get("verdict") not in ("justified", "unjustified") or not b.get("note"): return 400, {"error": "verdict + note required"}
            CON.execute("UPDATE requests SET review=?, reviewer=?, review_note=? WHERE id=?", (b["verdict"].upper(), u["name"], b["note"], rid)); CON.commit()
            audit(u["name"], "REVIEW", rid, {"verdict": b["verdict"], "note": b["note"]}); return 200, {"review": b["verdict"].upper()}

def use(u, m, b, h):  # stands in for the vault/PAM/jump host that validates the break-glass credential
    tok = h.get("X-Break-Glass-Token", "")
    with LOCK:
        r = CON.execute("SELECT * FROM requests WHERE token_hash=?", (hashlib.sha256(tok.encode()).hexdigest(),)).fetchone()
        if not r or r["state"] != "APPROVED" or r["expires"] < time.time():
            audit("unknown", "USE_DENIED", r["id"] if r else None, {"path": b.get("path")}); return 401, {"error": "invalid, expired or revoked"}
    audit(r["requester"], "USE", r["id"], {"resource": r["resource"], "path": b.get("path"), "op": b.get("op")})
    return 200, {"granted": r["resource"], "secret": "s3cr3t-FROM-VAULT", "seconds_left": int(r["expires"] - time.time())}

def audit_list(u, m, b, h):
    if u["role"] == "requester": return 403, {"error": "forbidden"}
    return 200, [dict(r) for r in CON.execute("SELECT seq,ts,actor,action,rid,detail,hash FROM audit ORDER BY seq DESC LIMIT 200")]
def verify_ep(u, m, b, h): return 200, verify()
def pending(u, m, b, h):
    if u["role"] != "auditor": return 403, {"error": "forbidden"}
    return 200, [_row(r) for r in CON.execute("SELECT * FROM requests WHERE review='PENDING'")]

ROUTES = [("POST", r"^/requests$", create), ("GET", r"^/requests$", listing), ("GET", r"^/requests/(\d+)$", one),
          ("POST", r"^/requests/(\d+)/(approve|deny|checkout|revoke|review)$", action), ("POST", r"^/vault/use$", use),
          ("GET", r"^/audit$", audit_list), ("GET", r"^/audit/verify$", verify_ep), ("GET", r"^/reviews/pending$", pending)]
UI = open(os.path.join(os.path.dirname(__file__), "ui.html"), "rb").read()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def _do(self, verb):
        if self.path == "/" and verb == "GET": return self._send(200, UI, "text/html")
        if self.path == "/health": return self._send(200, {"ok": True})
        sweep()
        try: body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError: return self._send(400, {"error": "bad json"})
        for v, pat, fn in ROUTES:
            mt = re.match(pat, self.path)
            if v == verb and mt:
                if fn is use: u = {}
                else:
                    u = USERS.get(self.headers.get("Authorization", "").replace("Bearer ", ""))
                    if not u: return self._send(401, {"error": "unauthenticated"})
                try: return self._send(*fn(u, mt.groups(), body, self.headers))
                except (KeyError, ValueError) as e: return self._send(400, {"error": f"bad input: {e}"})
        self._send(404, {"error": "no route"})
    def do_GET(self): self._do("GET")
    def do_POST(self): self._do("POST")

def serve(port=8080, db=None):
    init(db)
    def loop():
        while True: time.sleep(2); sweep()
    threading.Thread(target=loop, daemon=True).start()
    return ThreadingHTTPServer(("0.0.0.0", port), H)

if __name__ == "__main__":
    p = int(os.getenv("PORT", 8080)); print(f"break-glass UI -> http://localhost:{p}", flush=True); serve(p).serve_forever()
