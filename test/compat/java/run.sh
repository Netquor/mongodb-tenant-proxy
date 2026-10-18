#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v mvn >/dev/null && command -v java >/dev/null || { echo "java/mvn not available" >&2; exit 1; }
mvn -q -B compile exec:java
