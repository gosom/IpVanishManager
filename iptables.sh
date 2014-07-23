#!/bin/bash

iptables -F

# Allow incoming
iptables -A INPUT -i lo -j ACCEPT

# local
iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -s 192.168.0.0/16 -j ACCEPT

# incoming dns
iptables -A INPUT -p udp --sport 53 -j ACCEPT

# incoming from vpn server
iptables -A INPUT -s $1 -j ACCEPT
# other traffic block
iptables -A INPUT ! -i tun+ -j DROP

# Allow outgoing
iptables -A OUTPUT -o lo -j ACCEPT

# dns
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# allow traffic to vpn
iptables -A OUTPUT -d $1 -j ACCEPT

# local
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

# forbid other
iptables -A OUTPUT ! -o tun+ -j DROP
