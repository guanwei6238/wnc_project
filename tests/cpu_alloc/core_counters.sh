#!/bin/bash
# Print the COUNTERS of the wnc-gw core program (wnc_gw_ingress): packets, redirects (summed over all CPUs)
# without BTF, bpftool prints key and value as byte arrays (little-endian)
for m in $(bpftool -j prog show name wnc_gw_ingress | python3 -c 'import json, sys; print(*json.load(sys.stdin)["map_ids"])'); do
  bpftool -j map show id $m | grep -q '"percpu_array"' || continue
  bpftool -j map dump id $m | python3 -c '
import json, sys
n = lambda x: x if isinstance(x, int) else int.from_bytes(bytes(int(b, 16) for b in x), "little")
d = json.load(sys.stdin)
print(" ".join(str(sum(n(v["value"]) for v in e["values"])) for e in sorted(d, key=lambda e: n(e["key"]))))'
done
