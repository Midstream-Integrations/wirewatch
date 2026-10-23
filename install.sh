#!/usr/bin/env bash
# wirewatch installer for Ubuntu 22.04+/24.04 and Raspberry Pi OS (Bookworm)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo ./install.sh"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "==> Installing packages"
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark python3 openssl libcap2-bin >/dev/null
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive wireshark-common >/dev/null 2>&1 || true

echo "==> Creating service user"
getent group wireshark >/dev/null || groupadd --system wireshark
# chgrp clears file capabilities, so set capabilities after it
chgrp wireshark /usr/bin/dumpcap && chmod 750 /usr/bin/dumpcap
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
id wirewatch >/dev/null 2>&1 || useradd --system --home /var/lib/wirewatch --shell /usr/sbin/nologin wirewatch
usermod -aG wireshark wirewatch

echo "==> Copying files"
install -d -m 755 /opt/wirewatch/static
install -m 644 "$SRC/collector.py" "$SRC/web.py" "$SRC/unifi.py" "$SRC/intel.py" /opt/wirewatch/
install -m 644 "$SRC/static/index.html" "$SRC/static/map.html" /opt/wirewatch/static/
install -d -m 755 /opt/wirewatch/static/vendor
install -m 644 "$SRC"/static/vendor/* /opt/wirewatch/static/vendor/
install -d -o wirewatch -g wirewatch -m 750 /var/lib/wirewatch
install -d -m 750 -g wirewatch /etc/wirewatch /etc/wirewatch/tls

if [[ ! -f /etc/wirewatch/wirewatch.env ]]; then
  echo "==> Writing /etc/wirewatch/wirewatch.env"
  IFACE="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')"
  PASS="$(openssl rand -base64 18 | tr -d '/+=')"
  sed -e "s|^WW_IFACE=.*|WW_IFACE=${IFACE:-eth0}|" -e "s|^WW_PASSWORD=.*|WW_PASSWORD=${PASS}|" \
      "$SRC/wirewatch.env.example" > /etc/wirewatch/wirewatch.env
  chgrp wirewatch /etc/wirewatch/wirewatch.env && chmod 640 /etc/wirewatch/wirewatch.env
  echo "    Dashboard login: admin / ${PASS}"
  echo "    Capture interface set to ${IFACE:-eth0}. Change WW_IFACE to your mirror-port NIC."
fi

if [[ ! -f /etc/wirewatch/categories.conf ]]; then
  install -m 640 -g wirewatch "$SRC/categories.conf.example" /etc/wirewatch/categories.conf
fi

if [[ ! -f /etc/wirewatch/tls/cert.pem ]]; then
  echo "==> Creating self-signed TLS certificate"
  HN="$(hostname)"; IPS="$(hostname -I | tr ' ' '\n' | grep -v '^$' | sed 's/^/IP:/' | paste -sd, -)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=${HN}" \
    -addext "subjectAltName=DNS:${HN},DNS:${HN}.local${IPS:+,$IPS}" \
    -keyout /etc/wirewatch/tls/key.pem -out /etc/wirewatch/tls/cert.pem 2>/dev/null
  chgrp wirewatch /etc/wirewatch/tls/*.pem && chmod 640 /etc/wirewatch/tls/*.pem
fi

echo "==> Enabling services"
install -m 644 "$SRC"/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wirewatch-collector wirewatch-web wirewatch-unifi wirewatch-intel
systemctl restart wirewatch-collector wirewatch-web wirewatch-unifi wirewatch-intel

PORT="$(grep -E '^WW_PORT=' /etc/wirewatch/wirewatch.env | cut -d= -f2)"
[[ "$PORT" == "443" ]] && PORT=""
echo
echo "Done. Open https://$(hostname -I | awk '{print $1}')${PORT:+:$PORT}/"
echo "Logs: journalctl -u wirewatch-collector -u wirewatch-web -u wirewatch-unifi -u wirewatch-intel -f"
