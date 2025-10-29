# EXAMPLE ONLY: run on a linux intercepting host you control (root)
# send inbound TCP packets destined to port 5985 to NFQUEUE 1:
sudo iptables -I PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
# (remove when done)
sudo iptables -D PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
