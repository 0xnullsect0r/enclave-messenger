#!/usr/bin/env bash
# One stack, joined to the federation (RFC 0012): copy ops/compose, run
# this, answer the questions. It writes .env and the config files, brings
# the stack up, waits for the front to serve the descriptor, and hands
# the stack's application to one existing server — the registrar behind
# it checks the stack from the outside and the next list takes it.
#
#   ./setup.sh                       ask everything
#   ./setup.sh --domain d --operator o --family f --email e --known k
#   ./setup.sh --noninteractive --domain … (same flags, no questions)
#
# Afterwards: docker compose logs -f server, and `docker compose exec
# server enclave-server list` (once it exists) shows the list arriving.
set -euo pipefail
cd "$(dirname "$0")"

ask() { # prompt default var
  local answer
  read -r -p "$1 [$2]: " answer
  echo "${answer:-$2}"
}

DOMAIN= OPERATOR= FAMILY= EMAIL= KNOWN= NONINTERACTIVE=false
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=$2; shift 2 ;;
    --operator) OPERATOR=$2; shift 2 ;;
    --family) FAMILY=$2; shift 2 ;;
    --email) EMAIL=$2; shift 2 ;;
    --known) KNOWN=$2; shift 2 ;;
    --noninteractive) NONINTERACTIVE=true; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done
if [ "$NONINTERACTIVE" = false ]; then
  [ -z "$DOMAIN" ] && DOMAIN=$(ask "The stack's public domain" "")
  [ -z "$OPERATOR" ] && OPERATOR=$(ask "Operator name users see" "$(whoami)")
  [ -z "$FAMILY" ] && FAMILY=$(ask "Operator family (servers of one family never count as independent)" "$OPERATOR")
  [ -z "$EMAIL" ] && EMAIL=$(ask "Email for the TLS certificate (Let's Encrypt)" "")
  [ -z "$KNOWN" ] && KNOWN=$(ask "One existing server's address (its registrar takes the application)" "")
fi
for v in DOMAIN OPERATOR EMAIL KNOWN; do
  if [ -z "${!v}" ]; then echo "$v is required" >&2; exit 2; fi
done

if [ ! -f .env ]; then
  cat > .env <<EOF
DOMAIN=$DOMAIN
OPERATOR=$OPERATOR
FAMILY=$FAMILY
ACME_EMAIL=$EMAIL
TLS_MODE=acme
# Auto-federation (RFC 0012): this stack's API, and the registrar its
# application goes to (any listed server's address works).
FEDERATION_API=0.0.0.0:7447
REGISTRAR=https://$KNOWN
EOF
  echo ".env written"
else
  echo ".env exists; leaving it alone (add FEDERATION_API and REGISTRAR by hand if missing)"
fi
for f in config/*.toml.example; do
  target="config/$(basename "${f%.example}")"
  [ -f "$target" ] || cp "$f" "$target"
done

echo "== bringing the stack up (the certificate takes a moment)"
docker compose up -d
echo "== waiting for the front to serve the stack's descriptor"
for _ in $(seq 120); do
  if docker compose exec -T server enclave-server descriptor 2>/dev/null | grep -q .; then
    break
  fi
  sleep 5
done

echo "== the stack's witness descriptor, for the application"
mkdir -p public 2>/dev/null || docker compose exec -T witness sh -c \
  'enclave-witness descriptor /var/lib/enclave/public/witness-descriptor.bin' \
  || echo "(no witness descriptor; the application goes out without one)"

echo "== applying to https://$KNOWN (the registrar checks the stack from outside)"
docker compose exec -T server enclave-server apply "$KNOWN"
echo
echo "Done. The registrar takes the application into the next list; clients"
echo "see this stack at their next list refresh. docker compose logs -f"
echo "shows the list arriving (server: 'federation: …')."
