#!/bin/sh
# Move enx9c69d3241bd9 into netns "lan" to act as the LAN client on the same laptop.
# eno2 stays in the root ns as the WAN side. The two sides can only reach each other over the physical cables through the Pi.
set -e

ip netns add lan

# Moving an interface into a namespace clears its IPs, so set them again inside
ip link set enx9c69d3241bd9 netns lan
ip -n lan addr add 10.254.127.1/24 dev enx9c69d3241bd9
ip -n lan link set lo up
ip -n lan link set enx9c69d3241bd9 up

# The LAN client uses the Pi's LAN port as its gateway
ip -n lan route add default via 10.254.127.2

# WAN side (root ns); replace: no error if the address already exists
ip addr replace 10.254.254.1/24 dev eno2
ip link set eno2 up

# Return route (pure routing mode): packets to the LAN subnet go to the Pi's WAN port.
# Without it, replies take the default route out of wlo1.
ip route add 10.254.127.0/24 via 10.254.254.2
