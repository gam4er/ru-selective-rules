#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
[[ $# -eq 3 ]] || { echo 'Usage: sudo bash install.sh APP_ID INSTALLATION_ID /absolute/app.pem' >&2; exit 1; }
[[ $1 =~ ^[0-9]+$ && $2 =~ ^[0-9]+$ && $3 = /* && -f $3 ]] || { echo 'Invalid installation arguments' >&2; exit 1; }
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 -c 'import sys; assert sys.version_info >= (3,11)'
test -x /usr/local/lib/sing-box-vpn/sing-box-stable
test -x /usr/local/bin/xray
getent group ru-rules >/dev/null || groupadd --system ru-rules
for account in ru-rules-build ru-rules-publish; do
  id "$account" >/dev/null 2>&1 || useradd --system --gid ru-rules --home-dir /nonexistent --shell /usr/sbin/nologin "$account"
done
install -d -m 0755 /opt/ru-selective-rules
install -m 0644 "$src/rules.py" "$src/requirements.txt" "$src/THIRD-PARTY-NOTICES.txt" /opt/ru-selective-rules/
python3 -m venv /opt/ru-selective-rules/venv
/opt/ru-selective-rules/venv/bin/pip install --only-binary=:all: -r "$src/requirements.txt"
install -d -m 0750 -o root -g ru-rules /etc/ru-selective-rules /var/lib/ru-selective-rules
install -d -m 0750 -o ru-rules-build -g ru-rules /var/lib/ru-selective-rules/build
install -d -m 0700 -o ru-rules-publish -g ru-rules /var/lib/ru-selective-rules/publish
install -m 0600 -o root -g root "$3" /etc/ru-selective-rules/github-app.pem
if [[ ! -f /etc/ru-selective-rules/config.json ]]; then
  python3 - "$src/config.example.json" "$1" "$2" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]));c.update(app_id=sys.argv[2],installation_id=sys.argv[3])
with open('/etc/ru-selective-rules/config.json','w') as f:json.dump(c,f,indent=2)
PY
fi
chown root:ru-rules /etc/ru-selective-rules/config.json
chmod 0640 /etc/ru-selective-rules/config.json
install -m 0644 "$src"/systemd/* /etc/systemd/system/
printf '%s\n' '#!/bin/sh' 'exec /opt/ru-selective-rules/venv/bin/python /opt/ru-selective-rules/rules.py "$@"' > /usr/local/bin/ru-rules
chmod 0755 /usr/local/bin/ru-rules
systemctl daemon-reload
systemctl enable --now ru-selective-build.timer
echo 'Installed. Start first build: sudo systemctl start ru-selective-build.service'
echo 'Status: sudo ru-rules status; journalctl -u ru-selective-build -u ru-selective-publish'
