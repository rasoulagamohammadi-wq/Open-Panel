#!/usr/bin/env python3
"""Called by OpenVPN: `hooks.py auth` (auth-user-pass-verify via-env) and `hooks.py disconnect` (client-disconnect)."""
import os, sys, time, sqlite3, hashlib, hmac

DB = os.environ.get("PANEL_DB", os.path.dirname(os.path.abspath(__file__)) + "/panel.db")


def conn():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def auth():
    u, p = os.environ.get("username", ""), os.environ.get("password", "")
    r = conn().execute("select * from users where username=?", (u,)).fetchone()
    if not r or not r["enabled"]:
        return 1
    if r["expire"] and r["expire"] < time.time():
        return 1
    if r["quota"] and r["used"] >= r["quota"]:
        return 1
    h = hashlib.pbkdf2_hmac("sha256", p.encode(), bytes.fromhex(r["salt"]), 100000).hex()
    return 0 if hmac.compare_digest(h, r["phash"]) else 1


def disconnect():
    u = os.environ.get("common_name") or os.environ.get("username", "")
    b = int(os.environ.get("bytes_received", 0) or 0) + int(os.environ.get("bytes_sent", 0) or 0)
    c = conn()
    c.execute("update users set used=used+? where username=?", (b, u))
    c.commit()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        sys.exit(auth())
    disconnect()
