#!/bin/bash

echo "🕒 Entrypoint script started..."

# Default values if not set
WORKERS=${WORKERS:-4}
THREADS=${THREADS:-10}

# # Wait for Redis to be ready
# echo "🔄 Waiting for Redis to be available..."
# until redis-cli -h "${REDIS_HOST:-redis}" ping; do
#     echo "⏳ Redis is not available yet, retrying in 1s..."
#     sleep 1
# done
# echo "✅ Redis is up!"

# Initialize Redis with global_params
echo "⚙️ Running Redis initialization script..."
python /app/init_params.py

echo "🚀 Starting Gunicorn with workers=$WORKERS, threads=$THREADS"

# Start Gunicorn
exec gunicorn --bind 0.0.0.0:8080 --workers "$WORKERS" --threads "$THREADS" --preload run:app
