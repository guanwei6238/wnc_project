#!/bin/sh
# Undo netns.sh: move enx9c69d3241bd9 back to the root ns and delete netns "lan".

# Delete the return route first; otherwise, when enx gets 10.254.127.1 back,
# the connected route 10.254.127.0/24 dev enx collides with it and cannot be created.
ip route del 10.254.127.0/24 via 10.254.254.2

# Then move it back to the root ns explicitly (netns 1 = the namespace of PID 1).
# A plain `ip netns del` also returns the physical NIC to root, but asynchronously, so setting the IP right after may fail.
ip -n lan link set enx9c69d3241bd9 netns 1
ip netns del lan

# Back to the state of net.sh
ip addr add 10.254.127.1/24 dev enx9c69d3241bd9
ip link set enx9c69d3241bd9 up
