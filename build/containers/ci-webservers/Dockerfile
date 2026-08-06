# syntax=docker/dockerfile:1.7

ARG TEST_UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
FROM ${TEST_UBUNTU_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# Keep connector packages and APT indexes in this CI-only image so each
# install-test can exercise apt dependency resolution without downloading them.
ARG APT_REFRESH_WEEK=local
RUN set -eux; \
    test -n "$APT_REFRESH_WEEK"; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod 0755 /usr/sbin/policy-rc.d; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    apt-get install --no-install-recommends -y apache2 curl jq logrotate nginx; \
    rm -f /var/cache/apt/archives/*.deb; \
    apt-get install --download-only --no-install-recommends -y \
      libapache2-mod-security2 \
      libnginx-mod-http-modsecurity
