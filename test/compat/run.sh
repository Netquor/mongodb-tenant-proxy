#!/usr/bin/env bash
# Cross-driver compatibility suite. Usage: test/compat/run.sh [mongosh|node|python|java ...]
#
# Builds the proxy binary, starts it in appname mode (one proxy, tenants chosen
# by appName) and in static mode (one proxy per tenant), then runs each
# language's scenario against both. Upstream is a throwaway local replica set
# unless MTP_MONGO_ADDR=host:port points at an initiated single-node replica set.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

LANGS=("$@")
[ ${#LANGS[@]} -eq 0 ] && LANGS=(mongosh node python java)

echo ">> building proxy"
(cd "$ROOT" && go build -o "$WORK/proxy" ./cmd/mongodb-tenant-proxy)

if [ -n "${MTP_MONGO_ADDR:-}" ]; then
  UP="$MTP_MONGO_ADDR"
else
  MONGOD="${MTP_MONGOD_BIN:-mongod}"
  UPPORT="$(free_port)"; UP="127.0.0.1:$UPPORT"
  mkdir -p "$WORK/db"
  echo ">> starting $MONGOD on $UP"
  "$MONGOD" --dbpath "$WORK/db" --port "$UPPORT" --bind_ip 127.0.0.1 --replSet rs0 \
    --logpath "$WORK/mongod.log" --quiet &
  PIDS+=($!)
  SH="${MONGOSH:-mongosh}"
  for _ in $(seq 60); do
    "$SH" --quiet --port "$UPPORT" --eval 'rs.status().ok' >/dev/null 2>&1 && break
    "$SH" --quiet --port "$UPPORT" --eval "try{rs.initiate({_id:'rs0',members:[{_id:0,host:'$UP'}]})}catch(e){}" >/dev/null 2>&1 || true
    sleep 1
  done
fi
# wait for a writable primary
for _ in $(seq 60); do
  "${MONGOSH:-mongosh}" --quiet "mongodb://$UP/?directConnection=true" --eval 'db.hello().isWritablePrimary' 2>/dev/null | grep -q true && break
  sleep 1
done

# Change streams need pre/post images (MongoDB 6.0+, wire version 17); older
# upstreams must be rejected with CommandNotSupported (115) instead.
WIRE="$("${MONGOSH:-mongosh}" --quiet "mongodb://$UP/?directConnection=true" --eval 'db.hello().maxWireVersion' 2>/dev/null | tail -1)"
if [ "${WIRE:-0}" -ge 17 ]; then export COMPAT_CHANGE_STREAMS=1; else export COMPAT_CHANGE_STREAMS=0; fi
echo ">> upstream maxWireVersion=$WIRE changeStreams=$COMPAT_CHANGE_STREAMS"

start_proxy() { # name, auth-json -> echoes port
  local name="$1" auth="$2" port; port="$(free_port)"
  cat >"$WORK/$name.json" <<JSON
{"listen":"127.0.0.1:$port","upstream":{"addr":"$UP"},"tenant":{"field":"tenantId"},"auth":$auth,"logLevel":"warn"}
JSON
  "$WORK/proxy" serve -config "$WORK/$name.json" >"$WORK/$name.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 50); do (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && break; sleep 0.1; done
  echo "$port"
}
PA="$(start_proxy appname '{"mode":"appname"}')"
PS1="$(start_proxy static1 '{"mode":"static","staticTenant":"static-a"}')"
PS2="$(start_proxy static2 '{"mode":"static","staticTenant":"static-b"}')"

export COMPAT_UPSTREAM="mongodb://$UP/?directConnection=true"
export COMPAT_APPNAME_A="mongodb://127.0.0.1:$PA/?appName=tenant-a"
export COMPAT_APPNAME_B="mongodb://127.0.0.1:$PA/?appName=tenant-b"
export COMPAT_STATIC_A="mongodb://127.0.0.1:$PS1/"
export COMPAT_STATIC_B="mongodb://127.0.0.1:$PS2/"

fail=0
for l in "${LANGS[@]}"; do
  echo "==== $l"
  if ! "$HERE/$l/run.sh"; then echo "FAIL: $l"; fail=1; tail -n 10 "$WORK"/appname.log "$WORK"/static1.log "$WORK"/static2.log; else echo "PASS: $l"; fi
done
exit $fail
