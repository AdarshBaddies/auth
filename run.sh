#!/bin/sh

echo "Waiting for postgres to become healthy..."
/usr/bin/wait-for-it postgres:5432 --timeout=30 || { echo "Postgres not healthy, exiting."; exit 1; }

echo "Postgres is healthy. Running migrations..."
npm run migrate

echo "Starting Node.js server..."
npm run start
