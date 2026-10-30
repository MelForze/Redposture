FROM debian:13

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    curl --fail --silent --show-error --location \
      https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg \
      -o /usr/share/keyrings/proxmox-archive-keyring.gpg; \
    echo '136673be77aba35dcce385b28737689ad64fd785a797e57897589aed08db6e45  /usr/share/keyrings/proxmox-archive-keyring.gpg' | sha256sum -c -; \
    printf '%s\n' \
      'Types: deb' \
      'URIs: http://download.proxmox.com/debian/pve' \
      'Suites: trixie' \
      'Components: pve-no-subscription' \
      'Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/proxmox.sources; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod +x /usr/sbin/policy-rc.d; \
    apt-get update; \
    apt-get install -y --no-install-recommends pve-manager pve-cluster; \
    rm /usr/sbin/policy-rc.d; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    rm -f /etc/apt/sources.list.d/pve-enterprise.sources; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod +x /usr/sbin/policy-rc.d; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssh-server rsyslog; \
    rm /usr/sbin/policy-rc.d; \
    rm -f /etc/ssh/ssh_host_*; \
    sed -i '/module(load="imklog")/d' /etc/rsyslog.conf; \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/sbin/proxmox-lab-entrypoint
COPY healthcheck.sh /usr/local/sbin/proxmox-lab-healthcheck
RUN chmod 0755 /usr/local/sbin/proxmox-lab-entrypoint /usr/local/sbin/proxmox-lab-healthcheck

EXPOSE 8006
ENTRYPOINT ["/usr/local/sbin/proxmox-lab-entrypoint"]
