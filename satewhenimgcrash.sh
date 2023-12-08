#!/bin/bash

PG_CONF_DIR="<your_postgresql_data_directory>"
PG_CONF="$PG_CONF_DIR/postgresql.conf"
PG_HBA="$PG_CONF_DIR/pg_hba.conf"


echo "Enabling SSL in postgresql.conf..."
sed -i "s/#ssl = off/ssl = on/" $PG_CONF


echo "Copying SSL certificate and key..."
cp <path_to_your_ssl_certificate> $PG_CONF_DIR/server.crt
cp <path_to_your_ssl_key> $PG_CONF_DIR/server.key
chmod 600 $PG_CONF_DIR/server.key


echo "Configuring pg_hba.conf for SSL/TLS connections..."
echo "# TYPE  DATABASE        USER            ADDRESS                 METHOD" >> $PG_HBA
echo "# Require SSL for external connections" >> $PG_HBA
echo "hostssl all             all             0.0.0.0/0               md5" >> $PG_HBA


echo "Restarting PostgreSQL service..."
sudo systemctl restart postgresql

echo "Configuration complete."
