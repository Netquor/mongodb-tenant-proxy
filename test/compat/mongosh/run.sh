#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
${MONGOSH:-mongosh} --nodb --quiet --eval "$(cat scenario.js)"
