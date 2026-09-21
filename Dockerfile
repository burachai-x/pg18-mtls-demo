FROM php:8.3-fpm-alpine

# Install system packages
RUN apk add --no-cache \
    nginx \
    postgresql-libs \
    postgresql-client \
    openssl \
    curl \
    libxml2 \
    su-exec

# Install PHP extensions
RUN apk add --no-cache --virtual .build-deps \
    postgresql-dev curl-dev libxml2-dev oniguruma-dev \
    && docker-php-ext-install pdo pdo_pgsql simplexml curl mbstring \
    && apk del .build-deps

# Remove wget (CVE-2025-69194) — pulled as transitive dependency but not needed
RUN rm -f /usr/bin/wget

# Copy nginx config
COPY web/nginx.conf /etc/nginx/http.d/default.conf

# Hide PHP version
RUN echo "expose_php = Off" > /usr/local/etc/php/conf.d/hide-version.ini && \
    echo "display_errors = Off" >> /usr/local/etc/php/conf.d/hide-version.ini && \
    echo "log_errors = On" >> /usr/local/etc/php/conf.d/hide-version.ini

# Copy PHP app
COPY web/html/ /var/www/html/

# api.php belongs to the separate 'api' service — remove it from the portal image
# so the REST API can only be served by that container (nginx proxies to it).
RUN rm -f /var/www/html/api.php

# Client certs for mTLS are mounted as read-only volume at runtime (not baked into image)
# docker-compose: ./web/certs:/etc/postgresql-certs:ro

# Expose ports (HTTP redirect + HTTPS + S3 proxy)
EXPOSE 8180 8443 3901

# Start both nginx and php-fpm
# Privilege separation:
#   - nginx master runs as root (needed to manage workers, not for port binding — ports >1024)
#   - nginx worker processes run as 'nginx' user (configured in nginx.conf)
#   - php-fpm master runs as root (needed to manage pool and drop privileges)
#   - php-fpm worker processes run as 'www-data' (configured in www.conf)
# All request handling is done by non-root worker processes.
# su-exec is available for running scripts as www-data where needed.
# Container runs with read_only rootfs, no-new-privileges, and minimal capabilities
# (CHOWN, SETUID, SETGID, DAC_OVERRIDE, FOWNER — no NET_BIND_SERVICE needed).
COPY web/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Ensure runtime files are owned by www-data so PHP can write to /tmp
RUN mkdir -p /tmp/pg-certs && chown www-data:www-data /tmp/pg-certs

# Create writable directory on webrun volume for persistent key backup
RUN mkdir -p /run/app-data && chown www-data:www-data /run/app-data

CMD ["/entrypoint.sh"]
