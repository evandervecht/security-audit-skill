#!/bin/bash
# Provision the upload directory for the web app
set -euo pipefail

useradd -r appsvc || true

mkdir -p /var/www/uploads
chown -R appsvc:www-data /var/www/uploads
chmod -R 750 /var/www/uploads

install -o appsvc -g appsvc -m 640 config.ini /etc/app/config.ini
chmod 640 /etc/app/config.ini

systemctl restart app
