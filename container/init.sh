#!/bin/bash
set -e

MARKER="/var/lib/mysql/.p2s_initialized"

if [ ! -f "$MARKER" ]; then
    echo "[init] First boot — setting up database..."

    # Initialize MariaDB data dir if empty
    if [ ! -d "/var/lib/mysql/mysql" ]; then
        mariadb-install-db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1
    fi

    # Start MariaDB temporarily
    /usr/bin/mariadbd-safe --datadir=/var/lib/mysql &
    for i in $(seq 1 30); do
        if mariadb -u root -e "SELECT 1" > /dev/null 2>&1; then
            echo "[init] MariaDB ready"
            break
        fi
        sleep 1
    done

    # Create database and user
    mariadb -u root <<-EOSQL
        CREATE DATABASE IF NOT EXISTS wordpress;
        CREATE USER IF NOT EXISTS 'wpuser'@'%' IDENTIFIED BY 'wppass123';
        GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'%' WITH GRANT OPTION;
        CREATE USER IF NOT EXISTS 'wpuser'@'localhost' IDENTIFIED BY 'wppass123';
        GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost' WITH GRANT OPTION;
        FLUSH PRIVILEGES;
EOSQL
    echo "[init] Database 'wordpress' created"

    # Install WordPress tables
    php -r "
        define('ABSPATH', '/var/www/html/');
        define('WP_INSTALLING', true);
        require_once ABSPATH . 'wp-config.php';
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        wp_install('PHP2Shell Lab', 'admin', 'admin@lab.local', true, '', 'admin123');
    " 2>/dev/null && echo "[init] WordPress installed (admin/admin123)" || echo "[init] WP install via browser needed"

    # Stop temporary MariaDB
    killall mariadbd 2>/dev/null || true
    sleep 2

    touch "$MARKER"
    echo "[init] Setup complete"
fi

echo "[init] Starting services..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
