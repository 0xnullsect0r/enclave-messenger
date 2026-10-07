#!/usr/bin/env bash
# A local mixnet on this machine (no Docker): the nym-api stand-in, three
# mix nodes and a gateway on 127.0.0.1, all from a nym-node built with
# ci/nym-localnet/offline.patch. Writes $DIR/network.json and leaves the
# processes running (their PIDs in $DIR/pids).
#
#   ci/nym-localnet/run-local.sh /path/to/nym-node DIR
#   ENCLAVE_NYM_TOPOLOGY=DIR/network.json ENCLAVE_NYM_API=http://127.0.0.1:18000/ …
set -euo pipefail
BIN=$(realpath "$1")
DIR=$(realpath -m "$2")
HERE=$(dirname "$(realpath "$0")")
mkdir -p "$DIR/home"
: > "$DIR/pids"
API=http://127.0.0.1:18000/

(cd "$HERE" && exec python3 -m http.server 18000 --bind 127.0.0.1 -d api) \
  > "$DIR/api.log" 2>&1 &
echo $! >> "$DIR/pids"

node() { # name mode n extra...
  local name=$1 mode=$2 n=$3
  shift 3
  HOME="$DIR/home" ENCLAVE_NYM_OFFLINE=1 "$BIN" run --id "$name" \
    --accept-operator-terms-and-conditions --local --mode "$mode" \
    --public-ips 127.0.0.1 \
    --mixnet-bind-address "127.0.0.1:1000$n" \
    --verloc-bind-address "127.0.0.1:2000$n" \
    --http-bind-address "127.0.0.1:3000$n" \
    --nym-api-urls "$API" --nyxd-urls http://127.0.0.1:1/ \
    --unsafe-disable-replay-protection "$@" \
    > "$DIR/$name.log" 2>&1 &
  echo $! >> "$DIR/pids"
}
node mix1 mixnode 1
node mix2 mixnode 2
node mix3 mixnode 3
node gw entry-gateway 4 --entry-bind-address 127.0.0.1:9000 \
  --lp-control-bind-address 127.0.0.1:41264 --lp-data-bind-address 127.0.0.1:51264 \
  --enforce-zk-nyms false --lp-use-mock-ecash true
# A second gateway, so a client can switch (RT-02).
node gw2 entry-gateway 5 --entry-bind-address 127.0.0.1:9001 \
  --lp-control-bind-address 127.0.0.1:41265 --lp-data-bind-address 127.0.0.1:51265 \
  --enforce-zk-nyms false --lp-use-mock-ecash true

python3 "$HERE/topology.py" "$DIR/network.json" \
  mix=127.0.0.1:10001:30001 mix=127.0.0.1:10002:30002 mix=127.0.0.1:10003:30003 \
  gateway=127.0.0.1:10004:30004:9000 gateway=127.0.0.1:10005:30005:9001
