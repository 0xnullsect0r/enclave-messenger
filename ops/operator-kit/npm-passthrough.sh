#!/usr/bin/env bash
# For a stack behind Nginx Proxy Manager (deployment.md, "Behind a reverse
# proxy"): pass the stack's HTTPS through untouched, by the TLS server
# name, to the machine running the front, whose Enclave TLS profile needs
# a post-quantum handshake NPM can't make. NPM keeps serving every other
# name on 443 as before.
#
#   npm-passthrough.sh DOMAIN FRONT_IP [NPM_DIR] [CONTAINER]
#   npm-passthrough.sh --undo [NPM_DIR] [CONTAINER]
#
# NPM_DIR is the folder with NPM's compose file (default: the current
# folder); CONTAINER its container (default: the one running the
# jc21/nginx-proxy-manager image). Run as root on the proxy machine.
#
# It writes NPM's custom stream config (a listener on 4443 that reads the
# server name with ssl_preread: DOMAIN to FRONT_IP:443, everything else to
# NPM's own 443), checks it with `nginx -t` and removes it again if that
# fails, then maps the host's port 443 to 4443 in the compose file (a copy
# is kept as *.before-enclave) and recreates the container. NPM's sites
# then see 127.0.0.1 as the client address.
#
# Port 80 stays with NPM, which hands DOMAIN's plain-HTTP requests (the
# front's ACME answers and its redirect) to FRONT_IP:80 through a second
# custom file, http_top.conf, read before NPM's own proxy hosts.
set -euo pipefail

die() { echo "npm-passthrough: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"

if [ "${1:-}" = --undo ]; then
  UNDO=1; DIR=${2:-$PWD}; C=${3:-}
else
  UNDO=; DOMAIN=${1:?DOMAIN FRONT_IP [NPM_DIR] [CONTAINER]}; IP=${2:?FRONT_IP}; DIR=${3:-$PWD}; C=${4:-}
fi
cd "$DIR"
F=$(ls docker-compose.yml docker-compose.yaml compose.yml compose.yaml 2>/dev/null | head -n 1) \
  || true
[ -n "$F" ] || die "no compose file in $DIR (give NPM's folder as an argument)"
[ -n "$C" ] || C=$(docker ps --filter ancestor=jc21/nginx-proxy-manager:latest --format '{{.Names}}' | head -n 1)
[ -n "$C" ] || C=$(docker ps --format '{{.Names}} {{.Image}}' | awk '/nginx-proxy-manager/ {print $1; exit}')
[ -n "$C" ] || die "no Nginx Proxy Manager container running"
DATA=$(docker inspect "$C" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')
[ -n "$DATA" ] || die "can't find the /data volume of $C"
CONF=$DATA/nginx/custom/stream.conf
HTTP=$DATA/nginx/custom/http_top.conf
echo "container $C, data $DATA, compose file $DIR/$F"

if [ -n "$UNDO" ]; then
  [ -f "$F.before-enclave" ] && cp "$F.before-enclave" "$F"
  rm -f "$CONF"
  grep -q 'npm-passthrough.sh' "$HTTP" 2>/dev/null && rm -f "$HTTP"
  docker compose up -d
  echo "undone: NPM has 443 again and the passthrough is gone"
  exit 0
fi

mkdir -p "$(dirname "$CONF")"
[ -f "$CONF" ] && cp "$CONF" "$CONF.before-enclave"
cat > "$CONF" <<'NGINX'
# Enclave (ops/operator-kit/npm-passthrough.sh): TLS for @DOMAIN@ passed
# through untouched, by server name; every other name to NPM's own HTTPS.
map $ssl_preread_server_name $enclave_sni_upstream {
    @DOMAIN@ @IP@:443;
    default  127.0.0.1:443;
}
server {
    listen 4443;
    listen [::]:4443;
    ssl_preread on;
    proxy_connect_timeout 10s;
    proxy_pass $enclave_sni_upstream;
}
NGINX
sed -i -e "s/@DOMAIN@/$DOMAIN/g" -e "s/@IP@/$IP/g" "$CONF"
HTTP_NEW=
if [ ! -e "$HTTP" ] || grep -q 'npm-passthrough.sh' "$HTTP"; then
  HTTP_NEW=1
  cat > "$HTTP" <<NGINX
# Enclave (ops/operator-kit/npm-passthrough.sh): $DOMAIN's plain HTTP (ACME
# answers, the redirect to HTTPS) to its front.
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://$IP:80;
        proxy_set_header Host \$host;
    }
}
NGINX
else
  echo "note: $HTTP already exists; add a port-80 server for $DOMAIN to http://$IP:80 to it by hand"
fi
if ! docker exec "$C" nginx -t; then
  rm -f "$CONF"
  [ -n "$HTTP_NEW" ] && rm -f "$HTTP"
  [ -f "$CONF.before-enclave" ] && mv "$CONF.before-enclave" "$CONF"
  die "nginx refused the config; nothing changed"
fi
docker exec "$C" nginx -s reload

if ! grep -Eq "443:4443" "$F"; then
  [ -f "$F.before-enclave" ] || cp "$F" "$F.before-enclave"
  sed -i -E "s/(['\"]?)443:443(['\"]?)/\\1443:4443\\2/" "$F"
fi
grep -Eq "443:4443" "$F" || die "couldn't find the 443:443 port line in $F; map host 443 to 4443 by hand"
docker compose up -d
sleep 5
docker ps --filter "name=$C" --format '{{.Names}}  {{.Ports}}'
echo
echo "done. $DOMAIN's HTTPS now goes straight to $IP:443."
echo "Its plain HTTP goes to $IP:80, so the front can get its certificate."
echo "Undo: run this script again with --undo $DIR"
