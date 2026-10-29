# OpenVPN Web Panel

[فارسی](#فارسی) · [English](#english)

---

## English

A small web panel to manage an OpenVPN server: users with **traffic quota**, **expiry date**, **max simultaneous connections**, live sessions, and a one-click `.ovpn` download. Flask + SQLite, no heavy dependencies.

### Features
- Create / edit / disable / delete users (username + password login, no per-user certificates)
- Traffic quota (GB) and expiry date per user, with quick +30 / +90 / +365 day buttons
- Max simultaneous connections per user
- Live sessions list with a "disconnect" button
- Users that are disabled, expired, over quota or over the connection limit are disconnected automatically (checked every 15 s)
- Shared `.ovpn` file download, change admin password, light/dark theme, RTL Persian UI

### Requirements
Debian / Ubuntu server, root access, public IPv4. Tested only on Ubuntu.

### Install
```bash
git clone https://github.com/rasoulagamohammadi-wq/ovpn-panel.git
cd ovpn-panel
bash install.sh
```
Optional environment variables: `SERVER_HOST=1.2.3.4  VPN_PORT=1194  PANEL_PORT=8080`

The script prints the panel address and the admin password at the end. Open `1194/udp` and `8080/tcp` in your firewall.

### How it works
- OpenVPN authenticates users with `hooks.py` against the panel's SQLite database (`auth-user-pass-verify`).
- On disconnect, `hooks.py` adds the session's traffic to the user's usage.
- The panel talks to OpenVPN's local management interface (`127.0.0.1:7505`) to list and kick sessions.

### Update the UI only
Replace `/opt/ovpn-panel/index.html` and refresh the browser. The database is not touched.

### Security notes
- The panel is plain HTTP. Put it behind nginx/Caddy with HTTPS, or restrict the port to your own IP.
- Change the admin password after first login.
- Never commit `.env`, `panel.db` or `pki/` (they are in `.gitignore`).

### Files
| File | Purpose |
|---|---|
| `app.py` | Flask backend, API, session enforcement |
| `hooks.py` | OpenVPN auth and traffic accounting hook |
| `index.html` | Web UI |
| `install.sh` | Installer (OpenVPN, PKI, NAT, systemd services) |

### License
MIT

---

## فارسی

یک پنل تحت وب سبک برای مدیریت سرور OpenVPN: کاربر با **سقف حجم**، **تاریخ انقضا** و **حداکثر اتصال هم‌زمان**، لیست اتصال‌های زنده و دانلود فایل `.ovpn`. نوشته‌شده با Flask و SQLite.

### امکانات
- ساخت، ویرایش، غیرفعال‌سازی و حذف کاربر (ورود با نام کاربری و رمز، بدون گواهی جدا برای هر کاربر)
- سقف حجم (GB) و تاریخ انقضا برای هر کاربر، با دکمه‌های سریع +۳۰ / +۹۰ / +۳۶۵ روز
- حداکثر اتصال هم‌زمان برای هر کاربر
- لیست اتصال‌های فعال با دکمه قطع اتصال
- قطع خودکار کاربرِ غیرفعال، منقضی، بی‌حجم یا بیش از حد مجاز اتصال (هر ۱۵ ثانیه بررسی می‌شود)
- دانلود فایل `.ovpn`، تغییر رمز ادمین، تم روشن و تیره، رابط فارسی راست‌به‌چپ

### پیش‌نیاز
سرور Debian یا Ubuntu، دسترسی root و آی‌پی عمومی IPv4. فقط روی Ubuntu تست شده است.

### نصب
```bash
git clone https://github.com/rasoulagamohammadi-wq/ovpn-panel.git
cd ovpn-panel
bash install.sh
```
متغیرهای اختیاری: `SERVER_HOST=1.2.3.4  VPN_PORT=1194  PANEL_PORT=8080`

در پایان نصب، آدرس پنل و رمز ادمین چاپ می‌شود. پورت‌های `1194/udp` و `8080/tcp` را در فایروال باز کنید.

### طرز کار
- OpenVPN کاربرها را با `hooks.py` و از روی دیتابیس پنل احراز هویت می‌کند.
- بعد از قطع هر اتصال، `hooks.py` حجم مصرفی همان نشست را به مصرف کاربر اضافه می‌کند.
- پنل با رابط مدیریت محلی OpenVPN (`127.0.0.1:7505`) لیست اتصال‌ها را می‌خواند و اتصال‌ها را قطع می‌کند.

### آپدیت فقط ظاهر پنل
فایل `/opt/ovpn-panel/index.html` را جایگزین کنید و مرورگر را رفرش کنید. دیتابیس تغییر نمی‌کند.

### نکات امنیتی
- پنل با HTTP ساده اجرا می‌شود. آن را پشت nginx یا Caddy با HTTPS بگذارید یا پورت را فقط برای آی‌پی خودتان باز کنید.
- بعد از اولین ورود رمز ادمین را عوض کنید.
- فایل‌های `.env` و `panel.db` و پوشه `pki/` را هرگز در گیت‌هاب آپلود نکنید (در `.gitignore` هستند).

### فایل‌ها
| فایل | کاربرد |
|---|---|
| `app.py` | بک‌اند Flask، API و قطع خودکار اتصال‌ها |
| `hooks.py` | احراز هویت OpenVPN و ثبت مصرف |
| `index.html` | رابط وب |
| `install.sh` | نصب‌کننده (OpenVPN، گواهی، NAT، سرویس‌ها) |

### مجوز
MIT
