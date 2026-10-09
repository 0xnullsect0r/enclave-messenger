#!/usr/bin/env bash
# Three operators' stacks on one host, federated by a test foundation
# (CI jobs `federation-e2e-tcp` and `federation-e2e-localnet`;
# docs/13-operators.md).
#
#   ci/federation/gen.sh up      # build the federation and start it
#   ci/federation/gen.sh e2e     # run enclave-e2e against it (restarts B midway)
#   ci/federation/gen.sh shape   # TRANSPORT=nym, after e2e: capture the
#                                # device's link to its gateway, idle and
#                                # busy, and check the traffic shape
#   ci/federation/gen.sh bench   # TRANSPORT=nym: live_bench on the local
#                                # mixnet (connect, round trips, bulk,
#                                # memory) into $WORK/bench.json
#   ci/federation/gen.sh logs    # every stack's logs (on failure)
#   ci/federation/gen.sh down    # stop everything and remove the volumes
#
# Needs: docker with compose, openssl, and the host binaries
# target/release/enclave-admin and target/release/enclave-e2e. The image is
# $IMAGE (default enclave-server:ci, built from ops/docker/Dockerfile).
#
# Each stack runs the real compose file with the development override
# (server reachable on 127.0.0.1) and the e2e override (witnesses on a shared
# network). The foundation key is made here; the list is built from the
# descriptors the stacks sign, the way the foundation builds it. Every log
# is witnessed by the other two stacks' witnesses, threshold 2. Stack c keeps
# its server state in PostgreSQL (compose.postgres.yml).
#
# TRANSPORT=nym runs it over a local Nym mixnet instead
# (ops/compose/compose.localnet.yml, image $LOCALNET_IMAGE from
# ci/nym-localnet): every stack's ingress joins it, clients reach servers
# only at their ingresses' Nym addresses through $NYMD (enclave-nymd from
# the nym/ workspace), and stack b's push wakes cross the mixnet from its
# push egress to the push relay's ingress. Needs $NYM_IMAGE (the
# ops/docker/Dockerfile `nym` target) too. Stack a then also runs the
# foundation's credential gate (profile `foundation`), its proxy being
# $DEVPROXY (enclave-dev-proxy, signers of its own) on this host; the list
# names the gate, so enclave-e2e buys its zk-nym tickets there through
# nymd before connecting, trusting the test CA ($ENCLAVE_NYM_TEST_CA).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$ROOT/target/federation}
IMAGE=${IMAGE:-enclave-server:ci}
ADMIN=${ADMIN:-$ROOT/target/release/enclave-admin}
E2E=${E2E:-$ROOT/target/release/enclave-e2e}
STACKS=(a b c)
PUSH_PORT=${PUSH_PORT:-8099}
TRANSPORT=${TRANSPORT:-tcp}
NYM_IMAGE=${NYM_IMAGE:-enclave-nym:ci}
LOCALNET_IMAGE=${LOCALNET_IMAGE:-enclave-nym-localnet:ci}
NYMD=${NYMD:-$ROOT/nym/target/release/enclave-nymd}
# enclave-tord (a dev-direct build): nymd dials its gateway and nym-api
# through its SOCKS5 port, as a device does through Tor. Empty: directly.
TORD=${TORD:-}
DEVPROXY=${DEVPROXY:-$ROOT/nym/target/release/enclave-dev-proxy}
DEVPROXY_PORT=${DEVPROXY_PORT:-7449}
LOCALNET=$WORK/localnet
NYM_API=http://10.77.0.2:8000/

ln_dc() {
  LOCALNET_DIR=$LOCALNET LOCALNET_IMAGE=$LOCALNET_IMAGE \
    docker compose -p nym-localnet -f "$ROOT/ops/compose/compose.localnet.yml" "$@"
}

# The profiles a stack runs with.
profiles() {
  local s=$1 p=()
  [ "$s" = b ] && p+=(--profile push)
  [ "$TRANSPORT" = nym ] && p+=(--profile nym)
  [ "$s" = a ] && [ "$TRANSPORT" = nym ] && p+=(--profile foundation)
  echo "${p[@]}"
}

dc() {
  local s=$1 extra=()
  shift
  [ -f "$WORK/$s/compose.postgres.yml" ] && extra=(-f "$WORK/$s/compose.postgres.yml")
  [ -f "$WORK/$s/compose.localnet-stack.yml" ] && extra+=(-f "$WORK/$s/compose.localnet-stack.yml")
  docker compose -p "e2e-$s" --project-directory "$WORK/$s" \
    -f "$WORK/$s/compose.yml" -f "$WORK/$s/compose.dev.yml" -f "$WORK/$s/compose.e2e.yml" \
    "${extra[@]}" "$@"
}

n_of() { case $1 in a) echo 1 ;; b) echo 2 ;; c) echo 3 ;; esac; }

wait_healthy() {
  local s=$1 i
  for i in $(seq 1 90); do
    if ! dc "$s" ps -a --format '{{.Health}}' | grep -qv healthy; then
      return 0
    fi
    sleep 2
  done
  dc "$s" ps
  dc "$s" logs --tail 50
  echo "stack $s did not become healthy" >&2
  return 1
}

# A file from a service's volume (distroless images have no shell).
fetch() { # stack service path dest
  local i
  for i in $(seq 1 150); do
    dc "$1" cp "$2:$3" "$4" 2>/dev/null && test -s "$4" && return 0
    sleep 2
  done
  dc "$1" logs --tail 50 "$2"
  echo "no $3 in $1/$2" >&2
  return 1
}

localnet_up() {
  echo "== local mixnet"
  mkdir -p "$LOCALNET"
  chmod 0777 "$LOCALNET"
  docker network create --subnet 10.77.0.0/24 enclave-nymnet >/dev/null 2>&1 || true
  ln_dc up -d nym-api mix1 mix2 mix3 gateway
  ln_dc run --rm -T topology
  test -s "$LOCALNET/network.json"
}

up() {
  rm -rf "$WORK"
  mkdir -p "$WORK/foundation" "$WORK/tls"
  docker network create enclave-federation >/dev/null 2>&1 || true
  [ "$TRANSPORT" = nym ] && localnet_up

  echo "== foundation key"
  "$ADMIN" foundation-keygen "$WORK/foundation.key" "$WORK/foundation/foundation.pub"

  echo "== a test CA for the fronts"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 2 \
    -subj "/CN=enclave e2e CA" -keyout "$WORK/tls/ca.key" -out "$WORK/tls/ca.pem" 2>/dev/null

  if [ "$TRANSPORT" = nym ]; then
    echo "== the credential proxy stand-in (enclave-dev-proxy)"
    openssl rand -hex 24 > "$WORK/credgate-proxy-token"
    "$DEVPROXY" --listen "0.0.0.0:$DEVPROXY_PORT" --token-file "$WORK/credgate-proxy-token" \
      > "$WORK/dev-proxy.log" 2>&1 &
    echo $! > "$WORK/dev-proxy.pid"
  fi

  for s in "${STACKS[@]}"; do
    local n d others=() o
    n=$(n_of "$s")
    d=$WORK/$s
    mkdir -p "$d/config" "$d/foundation" "$d/tls" "$d/out"
    chmod 0777 "$d/out"
    cp "$ROOT"/ops/compose/compose.yml "$ROOT"/ops/compose/compose.dev.yml \
       "$ROOT"/ops/compose/compose.e2e.yml "$d/"
    [ "$TRANSPORT" = nym ] && cp "$ROOT"/ops/compose/compose.localnet-stack.yml "$d/"
    for f in "$ROOT"/ops/compose/config/*.toml.example; do
      cp "$f" "$d/config/$(basename "${f%.example}")"
    done
    for o in "${STACKS[@]}"; do [ "$o" != "$s" ] && others+=("\"http://witness-$o:7446\""); done
    sed -i "s|^witnesses = \[\]|witnesses = [$(IFS=,; echo "${others[*]}")]|" "$d/config/server.toml"
    # Stack b's due wakes: to its push egress over the mixnet, or straight
    # to the push relay on the dev transport ([push] is in the example).
    if [ "$s" = b ]; then
      local fwd=push-relay:7445
      [ "$TRANSPORT" = nym ] && fwd=push-egress:7446
      sed -i "s|^# forward = .*|forward = \"$fwd\"|" "$d/config/server.toml"
      grep -q "^forward = \"$fwd\"" "$d/config/server.toml"
    fi
    cat >> "$d/config/front.toml" <<EOF
tls = "files"
cert = "/etc/enclave/tls/cert.pem"
key = "/etc/enclave/tls/key.pem"
EOF
    # The front's certificate, for 127.0.0.1 under the test CA.
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
      -subj "/CN=$s.test" -keyout "$d/tls/key.pem" -out "$d/tls/req.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1,DNS:%s.test\n' "$s" > "$d/tls/ext.cnf"
    openssl x509 -req -in "$d/tls/req.csr" -CA "$WORK/tls/ca.pem" -CAkey "$WORK/tls/ca.key" \
      -CAcreateserial -days 2 -extfile "$d/tls/ext.cnf" -out "$d/tls/cert.pem" 2>/dev/null
    chmod 0644 "$d/tls/key.pem"
    cat > "$d/.env" <<EOF
ENCLAVE_IMAGE=${IMAGE%:*}
ENCLAVE_VERSION=${IMAGE##*:}
STACK=$s
DOMAIN=$s.test
OPERATOR=op-$s
FAMILY=fam-$s
TLS_MODE=files
RELAY_PUBLIC_ADDR=127.0.0.1:5182$n
FRONT_HTTP_PORT=808$n
FRONT_HTTPS_PORT=844$n
RELAY_PORT=5182$n
SERVER_PORT=744$n
ENCLAVE_NYM_IMAGE=${NYM_IMAGE%:*}
LOCALNET_DIR=$LOCALNET
EOF
    cp "$WORK/foundation/foundation.pub" "$d/foundation/"
    if [ "$s" = a ] && [ "$TRANSPORT" = nym ]; then
      # The foundation's credential gate, served by a's front; little work
      # per challenge, for CI.
      mkdir -p "$d/secrets"
      cp "$WORK/credgate-proxy-token" "$d/secrets/credgate-proxy-token"
      chmod 0444 "$d/secrets/credgate-proxy-token"
      sed -i 's/^effort = .*/effort = 50/' "$d/config/credgate.toml"
      cat >> "$d/.env" <<EOF
CREDGATE_PROXY_URL=http://host.docker.internal:$DEVPROXY_PORT
CREDGATE_UPSTREAM=http://credgate:7448
EOF
    fi
    if [ "$s" = c ]; then
      cp "$ROOT"/ops/compose/compose.postgres.yml "$d/"
      mkdir -p "$d/secrets"
      pw=$(openssl rand -hex 24)
      printf '%s' "$pw" > "$d/secrets/postgres_password"
      printf 'postgres://enclave:%s@postgres/enclave' "$pw" > "$d/secrets/database_url"
      chmod 0444 "$d/secrets/postgres_password" "$d/secrets/database_url"
    fi

    echo "== stack $s: keys and descriptors"
    dc "$s" run --rm -T server init | tail -1 > "$d/server.id"
    dc "$s" run --rm -T witness init >/dev/null
    dc "$s" run --rm -T relay init >/dev/null
    dc "$s" run --rm -T -v "$d/out:/out" server descriptor /out/server.bin --config /etc/enclave/server.toml >/dev/null
    dc "$s" run --rm -T -v "$d/out:/out" witness descriptor /out/witness.bin --config /etc/enclave/witness.toml >/dev/null
    dc "$s" run --rm -T -v "$d/out:/out" relay descriptor /out/relay.bin --config /etc/enclave/relay.toml >/dev/null
    echo "   server $(cat "$d/server.id")"
  done

  if [ "$TRANSPORT" = nym ]; then
    echo "== stack a: the credential gate's issuer keys"
    dc a run --rm -T credgate init --config /etc/enclave/credgate.toml >/dev/null
    dc a run --rm -T credgate show-key --config /etc/enclave/credgate.toml --epochs 2 \
      > "$WORK/credgate-keys.txt"
    cat "$WORK/credgate-keys.txt"
  fi

  echo "== push relay (stack b)"
  dc b run --rm -T push-relay init >/dev/null
  dc b --profile push up -d push-relay
  if [ "$TRANSPORT" = nym ]; then
    # Its ingress on the mixnet; every stack's push egress sends there.
    dc b --profile push up -d push-ingress
    fetch b push-ingress /var/lib/enclave/public/push-ingress.addr "$WORK/push-ingress.addr"
    for s in "${STACKS[@]}"; do
      echo "PUSH_RELAY_NYM=$(tr -d '\n' < "$WORK/push-ingress.addr")" >> "$WORK/$s/.env"
    done
  fi
  for _ in $(seq 1 30); do
    dc b cp push-relay:/var/lib/enclave/public/push-relay-keys.bin "$WORK/push-relay-keys.bin" 2>/dev/null && break
    sleep 1
  done
  test -s "$WORK/push-relay-keys.bin"

  echo "== the list"
  cat > "$WORK/spec.toml" <<EOF
seq = 1
valid_days = 7
witness_threshold = 2
EOF
  for s in "${STACKS[@]}"; do
    cat >> "$WORK/spec.toml" <<EOF
[[server]]
descriptor = "$s/out/server.bin"
weight = 1
[[witness]]
descriptor = "$s/out/witness.bin"
[[relay]]
descriptor = "$s/out/relay.bin"
EOF
  done
  cat >> "$WORK/spec.toml" <<EOF
[[push]]
nym_address = "e2e-push-relay"
keys = "push-relay-keys.bin"
EOF
  if [ "$TRANSPORT" = nym ]; then
    cat >> "$WORK/spec.toml" <<EOF
[[credgate]]
url = "https://127.0.0.1:8441"
issuer_name = "a.test"
keys = "credgate-keys.txt"
EOF
  fi
  "$ADMIN" server-list build "$WORK/spec.toml" --key "$WORK/foundation.key" \
    --out "$WORK/foundation/server-list.bin"
  "$ADMIN" server-list verify "$WORK/foundation/server-list.bin" \
    --foundation "$WORK/foundation/foundation.pub"

  echo "== start"
  for s in "${STACKS[@]}"; do
    cp "$WORK/foundation/server-list.bin" "$WORK/$s/foundation/"
    # Without the mixnet the push relay's ingress has nothing to join (and
    # its image isn't built): name the services to start without it, since
    # compose pulls images even for services scaled to zero.
    local only=()
    if [ "$s" = b ] && [ "$TRANSPORT" != nym ]; then
      # shellcheck disable=SC2046
      mapfile -t only < <(dc "$s" $(profiles "$s") config --services | grep -vx push-ingress)
    fi
    # shellcheck disable=SC2046
    dc "$s" $(profiles "$s") up -d "${only[@]}"
  done
  for s in "${STACKS[@]}"; do wait_healthy "$s"; done
  if [ "$TRANSPORT" = nym ]; then
    for s in "${STACKS[@]}"; do
      fetch "$s" ingress /var/lib/enclave/public/ingress.addr "$WORK/$s/ingress.addr"
      echo "   $s ingress $(cat "$WORK/$s/ingress.addr")"
    done
  fi

  echo "== fronts serve their servers' descriptors over the Enclave TLS profile"
  for s in "${STACKS[@]}"; do
    "$ADMIN" descriptor fetch "https://127.0.0.1:844$(n_of "$s")" --ca "$WORK/tls/ca.pem" \
      --id "$(cat "$WORK/$s/server.id")" --out "$WORK/$s/fetched.bin"
  done
}

servers_arg() {
  local s out=()
  for s in "${STACKS[@]}"; do
    if [ "$TRANSPORT" = nym ]; then
      out+=("$(cat "$WORK/$s/server.id")=nym:$(tr -d '\n' < "$WORK/$s/ingress.addr")")
    else
      out+=("$(cat "$WORK/$s/server.id")=127.0.0.1:744$(n_of "$s")")
    fi
  done
  IFS=,; echo "${out[*]}"
}

# enclave-e2e's arguments for every subcommand, in COMMON.
common_args() {
  COMMON=(--state "$WORK/e2e" --servers "$(servers_arg)"
    --foundation "$WORK/foundation/foundation.pub" --server-list "$WORK/foundation/server-list.bin")
  if [ "$TRANSPORT" = nym ]; then
    COMMON+=(--nymd "$NYMD")
    if [ -n "$TORD" ]; then COMMON+=(--tord "$TORD"); fi
    export ENCLAVE_NYM_TOPOLOGY=$LOCALNET/network.json ENCLAVE_NYM_API=$NYM_API
    # nymd reaches the gate at a's front, under the test CA (taken on a
    # local mixnet only).
    export ENCLAVE_NYM_TEST_CA=$WORK/tls/ca.pem
  fi
}

e2e() {
  common_args
  local common=("${COMMON[@]}")
  "$E2E" setup "${common[@]}" \
    --push-relay-keys "$WORK/push-relay-keys.bin" \
    --push-listen "0.0.0.0:$PUSH_PORT" \
    --push-endpoint "http://host.docker.internal:$PUSH_PORT/up"
  echo "== restarting stack b"
  # shellcheck disable=SC2046
  dc b $(profiles b) restart
  wait_healthy b
  "$E2E" after-restart "${common[@]}"
}

# The traffic-shape check (docs/09-transport.md §6.7): tcpdump on the
# mixnet's bridge records this host's link to the gateway's WebSocket port
# (both ways) while `enclave-e2e shape` runs Ada's shaped client idle, then busy;
# pcap-check.py compares the two and the model. Only the host's link is
# captured: the stacks' ingresses reach the gateway from their own
# addresses on the bridge.
shape() {
  if [ "$TRANSPORT" != nym ]; then
    echo "shape: TRANSPORT=nym only" >&2
    exit 2
  fi
  local out=$WORK/shape gateway=10.77.0.21 br host rc=0
  br=br-$(docker network inspect -f '{{.Id}}' enclave-nymnet | cut -c1-12)
  host=$(ip -4 -o addr show dev "$br" | awk '{print $4}' | cut -d/ -f1)
  rm -rf "$out"
  mkdir -p "$out"
  common_args
  echo "== capturing $host ↔ $gateway:9000 on $br"
  sudo tcpdump -Z root -i "$br" -n -s 0 -U -w "$out/link.pcap" \
    "tcp and host $host and host $gateway and port 9000" 2> "$out/tcpdump.log" &
  local capture=$!
  sleep 2
  "$E2E" shape "${COMMON[@]}" --marks "$out/marks" \
    --seconds "${SHAPE_SECONDS:-90}" --warmup "${SHAPE_WARMUP:-30}" \
    --profile "${SHAPE_PROFILE:-foreground}" || rc=$?
  sudo kill -INT "$capture" 2>/dev/null || true
  wait "$capture" || true
  cat "$out/tcpdump.log"
  [ "$rc" = 0 ] || return "$rc"
  python3 "$ROOT/ci/federation/pcap-check.py" "$out/link.pcap" "$out/marks" \
    --port 9000 --dst "$gateway" --src "$host" | tee "$out/report.txt"
  return "${PIPESTATUS[0]}"
}

# The mixnet path's numbers on the local mixnet (N4): live_bench from the
# nym/ workspace, its JSON in $WORK/bench.json. A regression check, not
# the M4 gate's device numbers (nym-live.yml measures live networks).
bench() {
  if [ "$TRANSPORT" != nym ]; then
    echo "bench: TRANSPORT=nym only" >&2
    exit 2
  fi
  ENCLAVE_NYM_TOPOLOGY=$LOCALNET/network.json ENCLAVE_NYM_API=$NYM_API RUST_LOG=off \
    "${BENCH:-$ROOT/nym/target/release/examples/live_bench}" --out "$WORK/bench.json"
}

down() {
  for s in "${STACKS[@]}"; do
    [ -d "$WORK/$s" ] && dc "$s" --profile push --profile nym --profile foundation down -v --remove-orphans || true
  done
  if [ -f "$WORK/dev-proxy.pid" ]; then
    kill "$(cat "$WORK/dev-proxy.pid")" 2>/dev/null || true
    rm -f "$WORK/dev-proxy.pid"
  fi
  docker network rm enclave-federation >/dev/null 2>&1 || true
  if [ "$TRANSPORT" = nym ]; then
    ln_dc down -v --remove-orphans || true
    docker network rm enclave-nymnet >/dev/null 2>&1 || true
  fi
}

logs() {
  for s in "${STACKS[@]}"; do
    [ -d "$WORK/$s" ] && dc "$s" --profile push --profile nym --profile foundation logs --no-color --tail 200 || true
  done
  [ -f "$WORK/dev-proxy.log" ] && cat "$WORK/dev-proxy.log" || true
  [ "$TRANSPORT" = nym ] && ln_dc logs --no-color --tail 100 || true
}

case "${1:-}" in
  up) up ;;
  e2e) e2e ;;
  shape) shape ;;
  bench) bench ;;
  logs) logs ;;
  down) down ;;
  *) echo "usage: $0 up|e2e|shape|bench|logs|down" >&2; exit 2 ;;
esac
