FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
  iproute2 iputils-ping net-tools curl wget nano \
  openssh-server nginx tcpdump ufw \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd
RUN echo "root:changeme" | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' 
/etc/ssh/sshd_config

EXPOSE 22 80

CMD bash -lc "\
  service nginx start && \
  /usr/sbin/sshd -D \
"


