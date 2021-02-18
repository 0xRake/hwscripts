#!/bin/bash

iptables -F -t nat
iptables -F
iptables --delete-chain
iptables -t nat --delete-chain

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i eth0 -j ACCEPT
iptables -A INPUT -s 192.168.12.0/24 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
#iptables -A INPUT -p tcp --dport 2000:2099 -j ACCEPT
#iptables -A INPUT -p tcp --dport 2100 -j ACCEPT

iptables -A INPUT -i ppp1 -p udp --dport 500 -j ACCEPT
iptables -A INPUT -i ppp1 -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -i ppp1 -p udp --dport 1701 -j ACCEPT
iptables -A INPUT -i ppp1 -p 50 -j ACCEPT
iptables -A INPUT -i ppp1 -p 51 -j ACCEPT
iptables -A INPUT -i ppp1 -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT

iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE
#iptables -A FORWARD -i eth0 -o ppp0 -j ACCEPT
#iptables -A FORWARD -i ppp0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT

#iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
#iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited

#iptables -A OUTPUT -j ACCEPT
iptables -I FORWARD -j ACCEPT
#iptables -A INPUT -j DROP

iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -L
exit;
