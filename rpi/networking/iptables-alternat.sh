# SSH GUARD
# install following tools
#

apt install sshguard iftop nload htop socat fail2ban

# Edit following IPTABLE Rules
iptables -N synfoold
iptables -N add-to-connlimit-list
iptables -N add-to-connlimit-list
iptables -N f2b-sshd
iptables -N f2b-SSH
iptables -N DOCKER
iptables -N sshguard

iptables -F

iptables -A INPUT -j sshguard
iptables -A INPUT -i lo -p all -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
#iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
#iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -j DROP -p icmp --icmp-type echo-request

iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j REJECT
iptables -A INPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j REJECT
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j REJECT
iptables -A INPUT -p tcp -m connlimit --connlimit-above 50 --connlimit-mask 32 --connlimit-saddr -j REJECT --reject-with tcp-reset
iptables -A  INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT
iptables -A  INPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
iptables -A  INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/sec --limit-burst 20 -j ACCEPT
iptables -A  INPUT -p tcp -m conntrack --ctstate NEW -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A INPUT -p tcp -m tcp --dport 22 -j f2b-SSH
iptables -A INPUT -p tcp -m tcp --dport 22 -j sshguard

iptables -A INPUT -p tcp -m tcp --dport 25 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 80,81,443,62222,10000 -j ACCEPT

iptables -A INPUT -p tcp -m multiport --dports 8080,8000,3000,30000 -j DROP
iptables -A INPUT -p tcp -m tcp --dport 53 -j DROP
iptables -A INPUT -p udp -m udp --dport 53 -j DROP

iptables -A INPUT -j REJECT

iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP

iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
iptables -t nat -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
iptables -t nat -A DOCKER -i docker0 -j RETURN