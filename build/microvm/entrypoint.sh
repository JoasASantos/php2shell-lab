#!/bin/bash
set -e

# Start hooks server FIRST so CourseStack ready check passes
python3 /opt/hooks_server.py &
echo "[init] Hooks server started on port 7681"

# Ensure MariaDB runtime dirs exist
mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld

echo "[init] Starting services..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
