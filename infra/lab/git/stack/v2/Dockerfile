# stack app image (P4b lab): PHP 8.3 CLI + pdo_pgsql. Same image runs `app` (php -S :8080) and
# `worker` (php /app/worker.php). Non-root (www-data). Classic-builder compatible.
FROM php:8.3-cli-alpine@sha256:6af812ec8035623727a7a9bfa41c6e8838e93dcad82e9119f33d9da130c5a472
RUN set -eux; \
    apk add --no-cache --virtual .build-deps $PHPIZE_DEPS postgresql-dev; \
    docker-php-ext-install pdo_pgsql; \
    apk del .build-deps; \
    apk add --no-cache libpq
COPY public/ /app/public/
COPY worker.php db.php /app/
USER www-data
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/app/public"]
