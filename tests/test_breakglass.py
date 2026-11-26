import json, os, sys, threading, time, unittest, urllib.request, urllib.error
os.environ["BG_UNIT_SECONDS"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import breakglass as bg

def call(port, method, path, tok=None, body=None, hdr=None):
    h = {"Content-Type": "application/json", **(hdr or {})}
    if tok: h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, headers=h, data=json.dumps(body or {}).encode())
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())

class T(unittest.TestCase):
    @classmethod
    def setUpClass(c):
        c.srv = bg.serve(0, ":memory:"); c.port = c.srv.server_address[1]
        threading.Thread(target=c.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(c): c.srv.shutdown()
    def c(self, *a, **k): return call(self.port, *a, **k)
    def mk(self, mins=1):
        return self.c("POST", "/requests", "t-alice", {"resource": "prod-db-root", "ticket": "INC-1", "minutes": mins, "reason": "P1 outage failover stuck"})[1]["id"]

    def test_full_lifecycle_and_audit(self):
        rid = self.mk(5)
        self.assertEqual(self.c("POST", f"/requests/{rid}/approve", "t-bob")[0], 200)
        _, co = self.c("POST", f"/requests/{rid}/checkout", "t-alice")
        self.assertEqual(self.c("POST", f"/requests/{rid}/checkout", "t-alice")[0], 409)   # one-time release
        self.assertEqual(self.c("POST", "/vault/use", hdr={"X-Break-Glass-Token": co["token"]}, body={"path": "/db"})[0], 200)
        self.c("POST", f"/requests/{rid}/revoke", "t-carol")
        self.assertEqual(self.c("POST", "/vault/use", hdr={"X-Break-Glass-Token": co["token"]})[0], 401)  # revoked
        self.assertEqual(self.c("POST", f"/requests/{rid}/review", "t-dave", {"verdict": "justified", "note": "matches INC-1"})[0], 200)
        self.assertTrue(self.c("GET", "/audit/verify", "t-dave")[1]["ok"])

    def test_dual_control(self):
        rid = self.mk()
        self.assertEqual(self.c("POST", f"/requests/{rid}/approve", "t-alice")[0], 403)   # requester cannot approve
        self.assertEqual(self.c("POST", f"/requests/{rid}/approve", "t-dave")[0], 403)    # auditor cannot approve
        self.assertEqual(self.c("POST", "/requests", "t-dave", {})[0], 403)

    def test_validation(self):
        self.assertEqual(self.c("POST", "/requests", "t-alice", {"resource": "x", "ticket": "bad", "minutes": 5, "reason": "long enough reason here"})[0], 400)
        self.assertEqual(self.c("POST", "/requests", "t-alice", {"resource": "x", "ticket": "INC-9", "minutes": 999, "reason": "long enough reason here"})[0], 400)
        self.assertEqual(self.c("GET", "/requests", "nope")[0], 401)

    def test_auto_expiry_forces_review(self):
        rid = self.mk(1); self.c("POST", f"/requests/{rid}/approve", "t-bob")
        tok = self.c("POST", f"/requests/{rid}/checkout", "t-alice")[1]["token"]; time.sleep(1.3)
        self.assertEqual(self.c("POST", "/vault/use", hdr={"X-Break-Glass-Token": tok})[0], 401)
        self.assertIn(rid, [r["id"] for r in self.c("GET", "/reviews/pending", "t-dave")[1]])

    def test_tamper_detected_and_triggers_block_edits(self):
        with self.assertRaises(Exception): bg.CON.execute("UPDATE audit SET actor='x' WHERE seq=1")
        bg.CON.execute("DROP TRIGGER audit_no_update"); bg.CON.execute("UPDATE audit SET actor='mallory' WHERE seq=1"); bg.CON.commit()
        v = self.c("GET", "/audit/verify", "t-dave")[1]; self.assertFalse(v["ok"]); self.assertEqual(v["broken_at"], 1)

if __name__ == "__main__": unittest.main()
