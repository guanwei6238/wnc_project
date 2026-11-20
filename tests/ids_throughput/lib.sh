#!/bin/bash
# Shared paths and the dk() function (runs commands in the container). Usage: source lib.sh
# Large files (slice pcaps, raw logs) go in $BIG outside the repo; the repo holds only scripts, the manifest and small results.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIG=${BIG:-/home/sixsquare/datasets/throughput}
PCAPS=$BIG/pcaps          # frozen slices (read-only)
RULES=$BIG/rules          # the four rule files + SHA256SUMS
RUNS=$BIG/runs            # raw logs of each run
IOT23=/home/sixsquare/datasets/iot23/extracted/run1/opt/Malware-Project/BigDataset/IoTScenarios
IMAGE=${IMAGE:-wnc-ids-lab}
mkdir -p "$PCAPS" "$RULES" "$RUNS"

# dk [extra docker args...] -- command...
# Why --network none: no network is needed at run time, and no new Docker subnet gets created (one clashed with the NAS's 172.24.8.x).
# Why --user: keeps the container from writing root-owned files the host cannot delete later.
dk() {
  local extra=()
  while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
  docker run --rm --network none --user "$(id -u):$(id -g)" "${extra[@]}" "$IMAGE" "$@"
}
