"""Bounded exhaustive model check of the refresh-token rotation state machine (formal-verification hook).

A pure-Python reference model (labels and dicts) runs in lock-step with the real ``TokenService`` (SQLite + JWT minting) for every
operation sequence up to a depth bound over this alphabet:

    refresh_A_newest   present the newest token of family A          refresh_A_first   present A's very first token (stale after 1st rotation)
    refresh_A_prev     present the token rotated most recently       refresh_B_newest  same for an unrelated family B
    revoke_A           revoke family A                               expire            advance the clock past the refresh TTL
    escalate_A         present A's newest token asking for a scope it was never granted

Checked after EVERY step:
    R1  the real result (ok / invalid_grant / invalid_scope) equals the model's
    R2  per family the number of active refresh tokens equals the model's, and is <= 1            (AUTH-1)
    R3  a revoked family has 0 active tokens and its access tokens introspect as inactive           (AUTH-2)
    R4  presenting a *used* token revokes its whole family (reuse detection) and never touches family B
    R5  scope escalation is refused without consuming the token
Bounded, not a proof for unbounded runs.
"""

import copy
import os
import shutil
import tempfile

from .auth import Authenticator, Keyring
from .tokens import AuthStore, GrantError, TokenService

ALPHABET = ("refresh_A_newest", "refresh_A_first", "refresh_A_prev", "refresh_B_newest", "revoke_A", "expire", "escalate_A")
REFRESH_TTL = 1000
ACCESS_TTL = 100


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


class ModelFamily:
    def __init__(self, now):
        self.tokens = [("t0", now + REFRESH_TTL)]
        self.status = {"t0": "active"}
        self.revoked = False
        self.access_exp = now + ACCESS_TTL

    def refresh(self, label, now):
        if self.status[label] == "revoked" or self.revoked:
            return "invalid_grant"
        if self.status[label] == "used":
            self.revoked = True
            self.status = {k: "revoked" for k in self.status}
            return "invalid_grant"
        exp = dict(self.tokens)[label]
        if now >= exp:
            self.status[label] = "revoked"
            return "invalid_grant"
        self.status[label] = "used"
        new = "t%d" % len(self.tokens)
        self.tokens.append((new, now + REFRESH_TTL))
        self.status[new] = "active"
        self.access_exp = now + ACCESS_TTL
        return "ok"

    def revoke(self):
        self.revoked = True
        self.status = {k: "revoked" for k in self.status}

    def counts(self):
        out = {}
        for s in self.status.values():
            out[s] = out.get(s, 0) + 1
        return out

    def newest(self):
        return self.tokens[-1][0]

    def prev(self):
        used = [l for l, _ in self.tokens if self.status[l] in ("used",)]
        return used[-1] if used else self.tokens[0][0]


def _setup(path, clock):
    os.makedirs(path, exist_ok=True)
    auth = Authenticator(Keyring(None, env_secret="refresh-model-check-secret-0123456789"), "http://mc", "aud", leeway=0, clock=clock)
    store = AuthStore(os.path.join(path, "auth.sqlite3"), clock=clock)
    auth.revocations = store
    return TokenService(auth, store, access_ttl=ACCESS_TTL, refresh_ttl=REFRESH_TTL), store


def check(depth=4, alphabet=ALPHABET, progress=None):
    base = tempfile.mkdtemp(prefix="mcpauth-rc-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
    clock = Clock()
    stats = {"depth": depth, "alphabet": len(alphabet), "nodes": 0, "sequences": 0, "violations": [], "results": {"ok": 0, "invalid_grant": 0, "invalid_scope": 0}}

    root = os.path.join(base, "n0")
    svc, store = _setup(root, clock)
    real0 = {}
    for fam in ("A", "B"):
        out = svc.issue("demo-client", "u" + fam, ["mcp", "tools:read", "offline_access"], offline=True)
        real0[fam] = {"tokens": {"t0": out["refresh_token"]}, "access": out["access_token"]}
        real0[fam]["fam"] = [r for r in [svc.auth.inspect(out["access_token"])["fam"]]][0]
    model0 = {"A": ModelFamily(clock()), "B": ModelFamily(clock())}

    def run_op(op, svc, model, real):
        now = clock()
        if op == "expire":
            clock.t += REFRESH_TTL + 1
            return "time"
        if op == "revoke_A":
            model["A"].revoke()
            svc.revoke_family(real["A"]["fam"], "mc")
            return "revoked"
        fam = "B" if "_B_" in op else "A"
        m, r = model[fam], real[fam]
        if op.endswith("newest") or op.startswith("escalate"):
            label = m.newest()
        elif op.endswith("first"):
            label = "t0"
        else:
            label = m.prev()
        if op.startswith("escalate"):
            want = "invalid_scope" if (not m.revoked and m.status[label] == "active" and now < dict(m.tokens)[label]) else m.refresh(label, now) if False else None
            if want is None:
                # not a clean escalation case: the grant checks (revoked/used/expired) win over scope; mirror them without consuming
                expected = m.refresh(label, now) if m.status[label] != "active" or m.revoked or now >= dict(m.tokens)[label] else "invalid_scope"
            else:
                expected = want
            scopes = ["mcp", "memory:admin"]
        else:
            expected = m.refresh(label, now)
            scopes = None
        try:
            out = svc.refresh(r["tokens"][label], "demo-client", scopes)
            got = "ok"
            idx = "t%d" % (len(r["tokens"]))
            r["tokens"][idx] = out["refresh_token"]
            r["access"] = out["access_token"]
        except GrantError as exc:
            got = exc.error
        return (expected, got)

    def verify(trace, svc, model, real, step):
        for fam in ("A", "B"):
            m, r = model[fam], real[fam]
            st = svc.family_state(r["fam"])
            counts = {k: v for k, v in st["counts"].items()}
            if counts != m.counts():
                stats["violations"].append({"trace": trace, "problem": "family %s counts real=%r model=%r" % (fam, counts, m.counts())})
            if counts.get("active", 0) > 1:
                stats["violations"].append({"trace": trace, "problem": "family %s has >1 active tokens" % fam})
            if st["revoked"] != m.revoked:
                stats["violations"].append({"trace": trace, "problem": "family %s revoked flag differs" % fam})
            if st["revoked"]:
                if counts.get("active", 0) != 0:
                    stats["violations"].append({"trace": trace, "problem": "revoked family %s has active tokens" % fam})
                if svc.introspect(r["access"])["active"]:
                    stats["violations"].append({"trace": trace, "problem": "revoked family %s access token still active" % fam})
            elif clock() < m.access_exp and not svc.introspect(r["access"])["active"]:
                stats["violations"].append({"trace": trace, "problem": "live family %s access token wrongly inactive" % fam})

    def explore(path, model, real, level, trace, t_now):
        if level == depth:
            stats["sequences"] += 1
            return
        for op in alphabet:
            child = path + "_%d" % stats["nodes"]
            shutil.copytree(path, child)
            stats["nodes"] += 1
            clock.t = t_now
            svc2, store2 = _setup(child, clock)
            m2, r2 = copy.deepcopy(model), copy.deepcopy(real)
            res = run_op(op, svc2, m2, r2)
            t2 = trace + [op]
            if isinstance(res, tuple):
                expected, got = res
                stats["results"][got] = stats["results"].get(got, 0) + 1
                if expected != got:
                    stats["violations"].append({"trace": t2, "problem": "result differs: model=%s real=%s" % (expected, got)})
            verify(t2, svc2, m2, r2, level)
            if len(stats["violations"]) < 5:
                explore(child, m2, r2, level + 1, t2, clock.t)
            shutil.rmtree(child, ignore_errors=True)
            if progress and stats["nodes"] % 500 == 0:
                progress(stats)

    explore(root, model0, real0, 0, [], clock.t)
    shutil.rmtree(base, ignore_errors=True)
    stats["ok"] = not stats["violations"]
    return stats
