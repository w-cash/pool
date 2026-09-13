FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus nginx curl openssl python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl mask getty.target console-getty.service \
    && touch /etc/zecwec-disposable-smoke
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
