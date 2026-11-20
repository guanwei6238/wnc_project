# Shared by all scripts: defines paths and dk() (runs a command in a container via docker). Usage: source lib.sh
# Why --network none: no network is needed at run time, and it avoids creating/occupying a Docker subnet (once clashed with the NAS subnet).
# Why --user: so the container does not write files as root that the host then cannot delete.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULESETS=/home/sixsquare/datasets/rulesets     # large files live outside the repo
WORK=$RULESETS/work                            # et_all.rules / converted rules (read-only /rules in the container)
RUNS=$RULESETS/runs                            # logs of each run (/out in the container)
IMAGE=wnc-ids-lab
mkdir -p "$WORK" "$RUNS"
# dk [extra docker args...] -- command...   e.g. dk --memory=1g --memory-swap=1g -- /scripts/ids.sh ...
dk() {
  local extra=()
  while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
  docker run --rm --network none --user "$(id -u):$(id -g)" \
    -v "$HERE":/scripts:ro -v "$WORK":/rules:ro -v "$RUNS":/out \
    "${extra[@]}" $IMAGE "$@"
}
