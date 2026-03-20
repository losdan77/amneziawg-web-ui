#!/bin/sh

# Cleanup iptables for WireGuard interface
# Usage: cleanup_iptables.sh <interface_name> <subnet> [egress_interface]

INTERFACE=$1
SUBNET=$2
EGRESS_INTERFACE=${3:-eth+}

if [ -z "$INTERFACE" ] || [ -z "$SUBNET" ]; then
    echo "Usage: $0 <interface_name> <subnet> [egress_interface]"
    echo "Example: $0 wg0 10.8.1.0/24 eth+"
    exit 1
fi

echo "Cleaning up iptables for interface $INTERFACE with subnet $SUBNET via $EGRESS_INTERFACE"

# Remove rules in reverse order
iptables -t nat -D POSTROUTING -s $SUBNET -o $EGRESS_INTERFACE -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $SUBNET -o eth+ -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $INTERFACE -o $EGRESS_INTERFACE -s $SUBNET -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -o $INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $INTERFACE -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i $INTERFACE -j ACCEPT 2>/dev/null || true

echo "iptables rules cleaned up successfully for $INTERFACE via $EGRESS_INTERFACE"