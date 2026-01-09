FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
  iproute2 iputils-ping net-tools curl wget nano \
  traceroute dnsutils nmap tcpdump openssh-client \
  && rm -rf /var/lib/apt/lists/*

CMD ["bash"]

