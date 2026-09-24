#!/bin/sh
set -e

# Setup iptables for WireGuard interface
# Usage: setup_iptables.sh <interface_name> <subnet> [egress_interface]

INTERFACE=$1
SUBNET=$2
EGRESS_INTERFACE=${3:-eth+}
LOCAL_INTERFACE=$(ip -4 route show default | awk 'NR == 1 {for (i=1;i<=NF;i++) if ($i == "dev") {print $(i+1); exit}}')
LOCAL_INTERFACE=${LOCAL_INTERFACE:-eth+}
if [ "$EGRESS_INTERFACE" = "eth+" ]; then
    EGRESS_INTERFACE=$LOCAL_INTERFACE
fi

if [ -z "$INTERFACE" ] || [ -z "$SUBNET" ]; then
    echo "Usage: $0 <interface_name> <subnet> [egress_interface]"
    echo "Example: $0 wg0 10.8.1.0/24 eth+"
    exit 1
fi

echo "Setting up iptables for interface $INTERFACE with subnet $SUBNET via $EGRESS_INTERFACE"

# Remove any existing rules for this interface to avoid duplicates
iptables -D INPUT -i $INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -o $INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $INTERFACE -o $EGRESS_INTERFACE -s $SUBNET -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $INTERFACE -o $EGRESS_INTERFACE -s $SUBNET -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $SUBNET -o $EGRESS_INTERFACE -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $SUBNET -o eth+ -j MASQUERADE 2>/dev/null || true
if [ "$LOCAL_INTERFACE" != "$EGRESS_INTERFACE" ] && [ "$LOCAL_INTERFACE" != "eth+" ]; then
    iptables -t nat -D POSTROUTING -s $SUBNET -o "$LOCAL_INTERFACE" -j MASQUERADE 2>/dev/null || true
fi

# Allow traffic on the TUN interface
iptables -A INPUT -i $INTERFACE -j ACCEPT
iptables -A FORWARD -i $INTERFACE -j ACCEPT
iptables -A OUTPUT -o $INTERFACE -j ACCEPT

# Allow forwarding traffic only from the VPN
# Match selected egress interface
iptables -A FORWARD -i $INTERFACE -o $EGRESS_INTERFACE -s $SUBNET -j ACCEPT

# Allow established and related connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Enable NAT for VPN traffic
iptables -t nat -A POSTROUTING -s $SUBNET -o $EGRESS_INTERFACE -j MASQUERADE

# In linked mode with split routing, some destinations may use local egress.
if [ "$EGRESS_INTERFACE" != "$LOCAL_INTERFACE" ]; then
    iptables -t nat -A POSTROUTING -s $SUBNET -o "$LOCAL_INTERFACE" -j MASQUERADE
fi

echo "iptables rules set up successfully for $INTERFACE via $EGRESS_INTERFACE"
