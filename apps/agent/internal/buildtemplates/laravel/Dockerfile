# pPanel built-in Dockerfile template: Laravel — written into the build context as Dockerfile.ppanel
# by the agent. Classic-builder compatible (no BuildKit-only syntax).
# Build stage: `composer install --no-dev` (scripts deferred, optimized autoloader).
# Runtime: php:8.3-apache serving public/ on :80 as non-root www-data (Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in container network namespaces, so no capability is needed).
# APP_KEY / DB_* etc. come from the deployment env/secrets at run time; nothing is cached at build time.
# Bases pinned by tag + multi-arch index digest (resolved 2026-11-23).
ARG COMPOSER_IMAGE=composer:2@sha256:50ea4d33fdcde1adb0f045547295faa1548b33872e5f789dae5b02ce2fb5de93
ARG PHP_IMAGE=php:8.3-apache@sha256:e520186957084dc0a5baaea83b2ef0c20b16e78c1de31b6fdb21dc1240cce42e

FROM ${COMPOSER_IMAGE} AS vendor
WORKDIR /app
COPY composer.json composer.lock* ./
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --no-scripts --no-autoloader --ignore-platform-reqs
COPY . .
RUN composer dump-autoload --no-dev --optimize --no-interaction --ignore-platform-reqs

FROM ${PHP_IMAGE} AS runtime
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libzip-dev libpq-dev libicu-dev; \
    docker-php-ext-install -j"$(nproc)" pdo_mysql pdo_pgsql zip intl bcmath opcache; \
    apt-get purge -y --auto-remove; \
    rm -rf /var/lib/apt/lists/*; \
    cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"; \
    a2enmod rewrite headers; \
    sed -ri -e 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/*.conf; \
    sed -ri -e 's!/var/www/!/var/www/html/public!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf; \
    printf '<Directory /var/www/html/public>\n  AllowOverride All\n  Require all granted\n</Directory>\nServerTokens Prod\nServerSignature Off\n' \
      > /etc/apache2/conf-available/ppanel-laravel.conf; \
    a2enconf ppanel-laravel; \
    mkdir -p /var/run/apache2 /var/lock/apache2; \
    chown -R www-data:www-data /var/run/apache2 /var/lock/apache2 /var/log/apache2
WORKDIR /var/www/html
COPY --chown=www-data:www-data . /var/www/html
COPY --from=vendor --chown=www-data:www-data /app/vendor /var/www/html/vendor
RUN set -eux; \
    rm -f Dockerfile.ppanel; \
    mkdir -p storage/framework/cache storage/framework/sessions storage/framework/views storage/logs bootstrap/cache; \
    chown -R www-data:www-data storage bootstrap/cache; \
    chmod -R ug+rwX storage bootstrap/cache
USER www-data
EXPOSE 80
CMD ["apache2-foreground"]
