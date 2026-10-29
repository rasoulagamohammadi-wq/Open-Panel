#!/usr/bin/env python3
"""OpenVPN web panel: users with traffic quota, expiry date, max connections."""
import os, re, time, socket, sqlite3, hashlib, hmac, secrets, threading, datetime, functools
from flask import Flask, request, jsonify, session, send_from_directory, Response

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("PANEL_DB", BASE + "/panel.db")
PKI = BASE + "/pki"
HOST = os.environ.get("SERVER_HOST", "YOUR_SERVER_IP")
PORT = os.environ.get("SERVER_PORT", "1194")
PROTO = os.environ.get("SERVER_PROTO", "udp")
MGMT = ("127.0.0.1", 7505)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


# ---------- database ----------
def q(sql, a=(), one=False):
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        rows = c.execute(sql, a).fetchall()
        c.commit()
        return (rows[0] if rows else None) if one else rows
    finally:
        c.close()


def hp(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100000).hex()


def mk(pw):
    s = secrets.token_hex(16)
    return s, hp(pw, s)


def kv(k):
    r = q("select v from kv where k=?", (k,), one=True)
    return r["v"] if r else None


def init():
    q("""create table if not exists users(
        id integer primary key autoincrement, username text unique not null,
        salt text, phash text, quota integer default 0, used integer default 0,
        expire integer default 0, max_conn integer default 1, enabled integer default 1,
        note text default '', created integer)""")
    q("create table if not exists kv(k text primary key, v text)")
    if not kv("admin_user"):
        s, h = mk(os.environ.get("ADMIN_PASS", "admin"))
        for k, v in (("admin_user", os.environ.get("ADMIN_USER", "admin")), ("admin_salt", s), ("admin_hash", h)):
            q("insert into kv values(?,?)", (k, v))


# ---------- OpenVPN management interface ----------
def mgmt(cmd):
    s = socket.create_connection(MGMT, timeout=5)
    f = s.makefile("rw")
    f.readline()  # banner
    f.write(cmd + "\n")
    f.flush()
    out = []
    while True:
        l = f.readline()
        if not l:
            break
        l = l.rstrip("\r\n")
        out.append(l)
        if l == "END" or l.startswith("SUCCESS") or l.startswith("ERROR"):
            break
    s.close()
    return out


def online():
    res = []
    for l in mgmt("status 3"):
        p = l.split("\t")
        if p[0] == "CLIENT_LIST" and len(p) >= 11:
            res.append(dict(user=p[1], ip=p[2], vip=p[3], rx=int(p[5]), tx=int(p[6]),
                            since=int(p[8]), cid=int(p[10])))
    return res


def safe_online():
    try:
        return online()
    except Exception:
        return []


def enforce():
    """Every 15s: disconnect users that are disabled, expired, over quota or over max connections."""
    while True:
        try:
            by = {}
            for s in safe_online():
                by.setdefault(s["user"], []).append(s)
            users = {r["username"]: r for r in q("select * from users")}
            now = time.time()
            for name, ss in by.items():
                u = users.get(name)
                live = sum(s["rx"] + s["tx"] for s in ss)
                bad = (not u or not u["enabled"] or (u["expire"] and u["expire"] < now)
                       or (u["quota"] and u["used"] + live >= u["quota"]))
                if bad:
                    kill = ss
                elif u["max_conn"] and len(ss) > u["max_conn"]:
                    kill = sorted(ss, key=lambda x: x["since"])[u["max_conn"]:]
                else:
                    kill = []
                for s in kill:
                    mgmt("client-kill %d" % s["cid"])
        except Exception as e:
            print("enforce:", e)
        time.sleep(15)


# ---------- auth ----------
def login_required(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get("ok"):
            return jsonify(error="auth"), 401
        return f(*a, **k)
    return w


fails = {}


@app.post("/api/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    ip, now = request.remote_addr, time.time()
    fails[ip] = [t for t in fails.get(ip, []) if now - t < 300]
    if len(fails[ip]) >= 5:
        return jsonify(error="تلاش بیش از حد. ۵ دقیقه صبر کنید."), 429
    if d.get("u") == kv("admin_user") and hmac.compare_digest(hp(str(d.get("p", "")), kv("admin_salt")), kv("admin_hash")):
        session["ok"] = True
        return jsonify(ok=1)
    fails[ip].append(now)
    return jsonify(error="نام کاربری یا رمز عبور اشتباه است."), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=1)


@app.post("/api/admin")
@login_required
def admin_pw():
    d = request.get_json(force=True, silent=True) or {}
    if not hmac.compare_digest(hp(str(d.get("old", "")), kv("admin_salt")), kv("admin_hash")):
        return jsonify(error="رمز فعلی اشتباه است."), 400
    if len(d.get("new", "")) < 8:
        return jsonify(error="رمز جدید باید حداقل ۸ کاراکتر باشد."), 400
    s, h = mk(d["new"])
    q("update kv set v=? where k='admin_salt'", (s,))
    q("update kv set v=? where k='admin_hash'", (h,))
    return jsonify(ok=1)


# ---------- users ----------
def parse(d):
    f = {}
    try:
        if "quota_gb" in d:
            f["quota"] = int(float(d["quota_gb"] or 0) * 1024 ** 3)
        if "expire" in d:
            f["expire"] = (int(datetime.datetime.strptime(d["expire"], "%Y-%m-%d").timestamp()) + 86399) if d["expire"] else 0
        if "max_conn" in d:
            f["max_conn"] = int(d["max_conn"] or 0)
    except ValueError:
        return None
    if "enabled" in d:
        f["enabled"] = int(bool(d["enabled"]))
    if "note" in d:
        f["note"] = str(d["note"])[:200]
    return f


@app.get("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.get("/api/users")
@login_required
def users():
    live = {}
    for s in safe_online():
        c, b = live.get(s["user"], (0, 0))
        live[s["user"]] = (c + 1, b + s["rx"] + s["tx"])
    out = []
    for u in q("select * from users order by id desc"):
        c, b = live.get(u["username"], (0, 0))
        out.append(dict(
            id=u["id"], username=u["username"], quota=u["quota"], used=u["used"] + b,
            expire=u["expire"], max_conn=u["max_conn"], enabled=u["enabled"], note=u["note"], online=c,
            expire_date=datetime.datetime.fromtimestamp(u["expire"]).strftime("%Y-%m-%d") if u["expire"] else ""))
    return jsonify(out)


@app.post("/api/users")
@login_required
def add():
    d = request.get_json(force=True, silent=True) or {}
    n = (d.get("username") or "").strip()
    f = parse(d)
    if f is None or not re.fullmatch(r"[A-Za-z0-9_.-]{2,32}", n) or len(d.get("password", "")) < 4:
        return jsonify(error="نام کاربری (حروف انگلیسی/عدد) یا رمز (حداقل ۴ کاراکتر) نامعتبر است."), 400
    s, h = mk(d["password"])
    try:
        q("insert into users(username,salt,phash,quota,expire,max_conn,enabled,note,created) values(?,?,?,?,?,?,?,?,?)",
          (n, s, h, f.get("quota", 0), f.get("expire", 0), f.get("max_conn", 1), f.get("enabled", 1), f.get("note", ""), int(time.time())))
    except sqlite3.IntegrityError:
        return jsonify(error="این نام کاربری قبلاً ثبت شده است."), 409
    return jsonify(ok=1)


@app.put("/api/users/<int:i>")
@login_required
def upd(i):
    d = request.get_json(force=True, silent=True) or {}
    f = parse(d)
    if f is None:
        return jsonify(error="مقدار نامعتبر."), 400
    if d.get("password"):
        if len(d["password"]) < 4:
            return jsonify(error="رمز حداقل ۴ کاراکتر باشد."), 400
        f["salt"], f["phash"] = mk(d["password"])
    if f:
        q("update users set " + ",".join(k + "=?" for k in f) + " where id=?", (*f.values(), i))
    return jsonify(ok=1)


@app.delete("/api/users/<int:i>")
@login_required
def rm(i):
    q("delete from users where id=?", (i,))
    return jsonify(ok=1)


@app.post("/api/users/<int:i>/reset")
@login_required
def reset(i):
    q("update users set used=0 where id=?", (i,))
    return jsonify(ok=1)


@app.get("/api/online")
@login_required
def onl():
    return jsonify(safe_online())


@app.post("/api/kill/<int:cid>")
@login_required
def kill(cid):
    try:
        mgmt("client-kill %d" % cid)
    except Exception:
        return jsonify(error="ارتباط با OpenVPN برقرار نشد."), 500
    return jsonify(ok=1)


@app.get("/api/ovpn")
@login_required
def ovpn():
    rd = lambda n: open(f"{PKI}/{n}").read().strip()
    cfg = f"""client
dev tun
proto {PROTO}
remote {HOST} {PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth-nocache
cipher AES-256-GCM
verb 3
<ca>
{rd('ca.crt')}
</ca>
<tls-crypt>
{rd('tc.key')}
</tls-crypt>
"""
    return Response(cfg, mimetype="application/x-openvpn-profile",
                    headers={"Content-Disposition": "attachment; filename=client.ovpn"})


if __name__ == "__main__":
    init()
    threading.Thread(target=enforce, daemon=True).start()
    app.run(os.environ.get("PANEL_BIND", "0.0.0.0"), int(os.environ.get("PANEL_PORT", "8080")), threaded=True)
