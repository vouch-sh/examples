FROM php:8.5-cli

RUN apt-get update && apt-get install -y unzip git libzip-dev && \
    docker-php-ext-install zip && \
    rm -rf /var/lib/apt/lists/*

COPY --from=composer:2.9 /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-interaction --prefer-dist

COPY . .
RUN composer dump-autoload

RUN cp .env.example .env && php artisan key:generate --force
RUN touch database/database.sqlite

EXPOSE 3000
RUN echo "variables_order = EGPCS" > /usr/local/etc/php/conf.d/env.ini
CMD ["php", "-S", "0.0.0.0:3000", "-t", "public"]
