FROM php:8.3-cli

RUN apt-get update && apt-get install -y unzip git libzip-dev && \
    docker-php-ext-install zip && \
    rm -rf /var/lib/apt/lists/*

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json ./
RUN composer install --no-dev --no-scripts

COPY . .
RUN composer dump-autoload

RUN php artisan key:generate --force 2>/dev/null || true
RUN touch database/database.sqlite

EXPOSE 3000
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=3000"]
