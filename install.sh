#!/bin/bash
# Usage (Debian/Ubuntu, as root):  bash install.sh
# Optional env: SERVER_HOST=1.2.3.4  VPN_PORT=1194  PANEL_PORT=8080
set -e
[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }

SRC=$(dirname "$(readlink -f "$0")")
APP=/opt/ovpn-panel
VPN_PORT=${VPN_PORT:-1194}
PANEL_PORT=${PANEL_PORT:-8080}
HOST=${SERVER_HOST:-$(curl -4 -s --max-time 8 https://ifconfig.me || hostname -I | awk '{print $1}')}

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openvpn easy-rsa python3-flask iptables curl openssl

mkdir -p $APP/pki
cp "$SRC/app.py" "$SRC/hooks.py" "$SRC/index.html" $APP/
chmod +x $APP/hooks.py

# --- PKI (server cert only; clients log in with username/password) ---
if [ ! -f $APP/pki/ca.crt ]; then
  make-cadir $APP/easy-rsa
  cd $APP/easy-rsa
  ./easyrsa --batch init-pki
  EASYRSA_REQ_CN=ovpn-ca ./easyrsa --batch build-ca nopass
  ./easyrsa --batch build-server-full server nopass
  cp pki/ca.crt pki/issued/server.crt pki/private/server.key $APP/pki/
  openvpn --genkey secret $APP/pki/tc.key 2>/dev/null || openvpn --genkey --secret $APP/pki/tc.key
  cd /
fi

# --- panel settings ---
if [ ! -f $APP/.env ]; then
  cat > $APP/.env <<EOF
ADMIN_USER=admin
ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=')
SECRET_KEY=$(openssl rand -hex 32)
SERVER_HOST=$HOST
SERVER_PORT=$VPN_PORT
SERVER_PROTO=udp
PANEL_PORT=$PANEL_PORT
EOF
  chmod 600 $APP/.env
fi

chown -R nobody:nogroup $APP
chown root:root $APP/.env $APP/pki/server.key
chmod 600 $APP/pki/server.key
chown -R root:root $APP/easy-rsa && chmod 700 $APP/easy-rsa

# --- OpenVPN server ---
cat > /etc/openvpn/server/server.conf <<EOF
port $VPN_PORT
proto udp
dev tun
ca $APP/pki/ca.crt
cert $APP/pki/server.crt
key $APP/pki/server.key
dh none
tls-crypt $APP/pki/tc.key
server 10.8.0.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 60
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
user nobody
group nogroup
persist-key
persist-tun
verb 3

# login with username/password checked against the panel database
verify-client-cert none
username-as-common-name
duplicate-cn
script-security 3
auth-user-pass-verify "$APP/hooks.py auth" via-env
client-disconnect "$APP/hooks.py disconnect"
management 127.0.0.1 7505
EOF

mkdir -p /etc/systemd/system/openvpn-server@server.service.d
printf '[Service]\nLimitNPROC=infinity\n' > /etc/systemd/system/openvpn-server@server.service.d/override.conf

# --- forwarding + NAT ---
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-ovpn.conf
sysctl -p /etc/sysctl.d/99-ovpn.conf >/dev/null
IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')
cat > /etc/systemd/system/ovpn-nat.service <<EOF
[Unit]
Description=NAT for OpenVPN clients
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $IF -j MASQUERADE
ExecStop=/sbin/iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $IF -j MASQUERADE
[Install]
WantedBy=multi-user.target
EOF

# --- panel service ---
cat > /etc/systemd/system/ovpn-panel.service <<EOF
[Unit]
Description=OpenVPN web panel
After=network.target
[Service]
User=nobody
Group=nogroup
WorkingDirectory=$APP
EnvironmentFile=$APP/.env
ExecStart=/usr/bin/python3 $APP/app.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ovpn-nat ovpn-panel
systemctl enable openvpn-server@server
systemctl restart openvpn-server@server

set -a; . $APP/.env; set +a
echo
echo "================ DONE ================"
echo "Panel : http://$HOST:$PANEL_PORT"
echo "User  : $ADMIN_USER"
echo "Pass  : $ADMIN_PASS   (change it from the panel)"
echo "Open ports: $VPN_PORT/udp and $PANEL_PORT/tcp"
