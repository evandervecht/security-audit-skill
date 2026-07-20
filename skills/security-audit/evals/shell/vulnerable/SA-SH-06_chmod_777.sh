#!/bin/bash
# Provision the upload directory for the web app
set -e

useradd -r appsvc || true

mkdir -p /var/www/uploads
chmod -R 777 /var/www/uploads

cp config.ini /etc/app/config.ini
chmod 777 /etc/app/config.ini

systemctl restart app
