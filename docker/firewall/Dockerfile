FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
  iproute2 iputils-ping net-tools nano \
  iptables ufw tcpdump \
  && rm -rf /var/lib/apt/lists/*

CMD ["bash", "-lc", "tail -f /dev/null"]

