#!/usr/bin/env bash
# Start a single-node replica set from the official image, reachable as 127.0.0.1:$PORT.
# usage: start-mongo.sh <version> [port]   (container is named "mongo-compat-<port>")
set -euo pipefail
v="$1"; port="${2:-27017}"; name="mongo-compat-$port"
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "127.0.0.1:$port:$port" "mongo:$v" --port "$port" --replSet rs0 --bind_ip_all >/dev/null
SH="$(docker exec "$name" sh -c 'command -v mongosh >/dev/null && echo mongosh || echo mongo')"
for _ in $(seq 60); do docker exec "$name" "$SH" --port "$port" --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break; sleep 1; done
docker exec "$name" "$SH" --port "$port" --quiet --eval "rs.initiate({_id:'rs0',members:[{_id:0,host:'127.0.0.1:$port'}]})" >/dev/null
for _ in $(seq 60); do
  docker exec "$name" "$SH" --port "$port" --quiet --eval 'db.hello().isWritablePrimary' 2>/dev/null | grep -q true && exit 0
  sleep 1
done
echo "replica set did not become primary" >&2; docker logs "$name" | tail -20; exit 1
