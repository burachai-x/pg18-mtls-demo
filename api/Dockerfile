# API APP — separate service from the web portal.
# Serves only the REST API (api.php); no UI pages, no S3/object-storage access.
# Build context is the repo root (shared PHP files live in web/html/).
FROM php:8.3-fpm-alpine

# Install system packages — deliberately smaller than the web image:
# no curl/libxml (API does not talk to object storage), no postgresql-client.
RUN apk add --no-cache \
    nginx \
    postgresql-libs \
    su-exec

# Install PHP extensions (API only needs PDO/pgsql + mbstring)
RUN apk add --no-cache --virtual .build-deps \
    postgresql-dev oniguruma-dev \
    && docker-php-ext-install pdo pdo_pgsql mbstring \
    && apk del .build-deps

# Remove wget (CVE-2025-69194) — pulled as transitive dependency but not needed
RUN rm -f /usr/bin/wget

# nginx config (TLS only, serves api.php exclusively)
COPY api/nginx.conf /etc/nginx/http.d/default.conf

# PHP hardening + session path of its own (the /tmp volume is shared with web
# so the crypto key stays in sync after rotation — sessions must not collide)
RUN echo "expose_php = Off" > /usr/local/etc/php/conf.d/hide-version.ini && \
    echo "display_errors = Off" >> /usr/local/etc/php/conf.d/hide-version.ini && \
    echo "log_errors = On" >> /usr/local/etc/php/conf.d/hide-version.ini && \
    echo "session.save_path = /tmp/api-sessions" > /usr/local/etc/php/conf.d/api-session.ini

# Only the PHP files the API actually needs — no index.php, upload.php, s3.php, …
COPY web/html/api.php  /var/www/html/api.php
COPY web/html/crud.php /var/www/html/crud.php
COPY web/html/db.php   /var/www/html/db.php
COPY web/html/mask.php /var/www/html/mask.php

# Client cert (CN=apiapp) and server cert are mounted read-only at runtime:
# docker-compose: ./api/certs:/etc/api-certs:ro

EXPOSE 8443

COPY api/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Writable dirs owned by www-data (rootfs is read-only at runtime)
RUN mkdir -p /tmp/api-pg-certs /tmp/api-sessions && \
    chown www-data:www-data /tmp/api-pg-certs /tmp/api-sessions

CMD ["/entrypoint.sh"]
