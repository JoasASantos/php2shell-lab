FROM php:8.4.26-apache

LABEL maintainer="Joas A Santos (@c0d3cr4zy)"
LABEL description="PHP2Shell Lab - CVE-2026-109618/CVE-2026-109619 Vulnerable WordPress"
LABEL version="1.0"

# Install PHP extensions for WordPress + lab dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev \
    libonig-dev libxml2-dev mariadb-client mariadb-server \
    unzip curl supervisor python3 procps \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
        mysqli pdo_mysql gd mbstring xml zip opcache exif \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

# Install WordPress
RUN curl -o /tmp/wp.tar.gz https://wordpress.org/latest.tar.gz \
    && tar -xzf /tmp/wp.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/wp.tar.gz \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# PHP config — vulnerable settings
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini
COPY php.ini /usr/local/etc/php/conf.d/zz-lab.ini
COPY apache.conf /etc/apache2/conf-enabled/zz-lab.conf
COPY wp-config.php /var/www/html/wp-config.php

# Health endpoint for exploit (WP bootstrap too heavy for B1 heap layout)
RUN echo '<?php echo "OK\n"; ?>' > /var/www/html/health.php \
    && chown www-data:www-data /var/www/html/health.php

# MariaDB directories
RUN mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld \
    && mkdir -p /var/lib/mysql && chown mysql:mysql /var/lib/mysql

# PRE-INITIALIZE MariaDB + WordPress during build (not runtime)
RUN mariadb-install-db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1 \
    && /usr/bin/mariadbd-safe --datadir=/var/lib/mysql & \
    sleep 5 \
    && for i in $(seq 1 30); do mariadb -u root -e "SELECT 1" > /dev/null 2>&1 && break || sleep 1; done \
    && mariadb -u root -e "\
        CREATE DATABASE IF NOT EXISTS wordpress; \
        CREATE USER IF NOT EXISTS 'wpuser'@'%' IDENTIFIED BY 'wppass123'; \
        GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'%' WITH GRANT OPTION; \
        CREATE USER IF NOT EXISTS 'wpuser'@'localhost' IDENTIFIED BY 'wppass123'; \
        GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost' WITH GRANT OPTION; \
        FLUSH PRIVILEGES;" \
    && php -r "\
        define('ABSPATH', '/var/www/html/'); \
        define('WP_INSTALLING', true); \
        require_once ABSPATH . 'wp-config.php'; \
        require_once ABSPATH . 'wp-admin/includes/upgrade.php'; \
        wp_install('PHP2Shell Lab', 'admin', 'admin@lab.local', true, '', 'admin123');" \
    && killall mariadbd && sleep 3 \
    && chown -R mysql:mysql /var/lib/mysql

# Supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# CourseStack microvm hooks
COPY microvm/hooks_server.py /opt/hooks_server.py
COPY microvm/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 7681

CMD ["/usr/local/bin/entrypoint.sh"]
