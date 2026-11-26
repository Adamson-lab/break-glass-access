"""Self-contained live demo: boots the service, runs a P1 incident end to end, then an attacker tampers with the log."""
import json, os, sys, threading, sqlite3, tempfile, urllib.request, urllib.error
os.environ.setdefault("BG_UNIT_SECONDS", "60")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import breakglass as bg, io, contextlib
db = os.path.join(tempfile.mkdtemp(), "demo.db"); srv = bg.serve(0, db); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
def call(m, p, tok=None, body=None, hdr=None):
    r = urllib.request.Request(f"http://127.0.0.1:{port}{p}", method=m, data=json.dumps(body or {}).encode(),
        headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + tok} if tok else {}), **(hdr or {})})
    try:
        with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())
def step(t, res): print(f"\n\033[1m▶ {t}\033[0m\n  {res[0]} {json.dumps(res[1])[:150]}")
q = io.StringIO()
with contextlib.redirect_stdout(q): pass
step("alice (SRE) raises P1 request", call("POST", "/requests", "t-alice", {"resource": "prod-db-root", "ticket": "INC-4521", "minutes": 15, "reason": "Payments DB failover stuck, customers impacted"}))
step("alice tries to approve her own request  → must FAIL", call("POST", "/requests/1/approve", "t-alice"))
step("bob (second person) approves", call("POST", "/requests/1/approve", "t-bob"))
s, co = call("POST", "/requests/1/checkout", "t-alice"); step("alice checks out one-time credential", (s, {"token": co["token"][:14] + "…"}))
step("alice uses it on the vault", call("POST", "/vault/use", body={"path": "/db/payments", "op": "failover"}, hdr={"X-Break-Glass-Token": co["token"]}))
step("alice tries to check out again → must FAIL", call("POST", "/requests/1/checkout", "t-alice"))
step("carol revokes: incident resolved", call("POST", "/requests/1/revoke", "t-carol"))
step("stolen token replayed after revoke → must FAIL", call("POST", "/vault/use", hdr={"X-Break-Glass-Token": co["token"]}))
step("dave (auditor) completes mandatory review", call("POST", "/requests/1/review", "t-dave", {"verdict": "justified", "note": "Matches INC-4521 timeline"}))
print("\n\033[1m▶ AUDIT TRAIL\033[0m")
for e in reversed(call("GET", "/audit", "t-dave")[1]): print(f"  #{e['seq']:<2} {e['actor']:<8} {e['action']:<22} req={e['rid']} {e['hash'][:10]}")
step("verify chain", call("GET", "/audit/verify", "t-dave"))
print("\n\033[1;31m▶ ATTACKER (DBA) disables trigger and rewrites history: alice → 'bob'\033[0m")
c = sqlite3.connect(db); c.execute("DROP TRIGGER audit_no_update"); c.execute("UPDATE audit SET actor='bob' WHERE action='USE'"); c.commit()
step("verify chain again → TAMPER DETECTED", call("GET", "/audit/verify", "t-dave"))
