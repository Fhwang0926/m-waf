ARG CUSTOMER_BASE_IMAGE=docker.io/library/ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
FROM ${CUSTOMER_BASE_IMAGE}

ARG WEB_SERVER
ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    case "$WEB_SERVER" in \
      apache) packages="apache2 libapache2-mod-security2"; service=apache2 ;; \
      nginx) packages="nginx libnginx-mod-http-modsecurity"; service=nginx ;; \
      *) echo "unsupported WEB_SERVER: $WEB_SERVER" >&2; exit 2 ;; \
    esac; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod 0755 /usr/sbin/policy-rc.d; \
    apt-get update; \
    apt-get install --no-install-recommends -y systemd systemd-sysv dbus ca-certificates curl logrotate $packages; \
    systemctl enable "$service"; \
    rm -f /usr/sbin/policy-rc.d; \
    rm -rf /var/lib/apt/lists/*; \
    printf 'M-WAF E2E OK\n' > /var/www/html/index.html; \
    printf 'M-WAF E2E BLOCK TARGET\n' > /var/www/html/mwaf-e2e-block; \
    printf 'M-WAF E2E EXCLUDED TARGET\n' > /var/www/html/mwaf-e2e-excluded

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
