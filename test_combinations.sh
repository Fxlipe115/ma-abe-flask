#!/bin/bash

LOGFILE="gunicorn_docker_test_results.csv"

# Define test parameters (workers, threads)
WORKERS_LIST=(2 4 8)
THREADS_LIST=(5 10 20)

set -e

# Create log file
echo "Workers,Threads,Requests/Second,Avg Response Time,Max Response Time" > $LOGFILE

# Start services without Gunicorn running
docker-compose -f docker-compose.yml up -d --build

for WORKERS in "${WORKERS_LIST[@]}"; do
  for THREADS in "${THREADS_LIST[@]}"; do
    echo "🔹 Testing Workers=$WORKERS, Threads=$THREADS"

    # Gracefully stop Gunicorn if running
    docker-compose exec web sh -c "pkill gunicorn || true"

    # Start Gunicorn with the new settings inside the container
    docker-compose exec -d web sh -c "gunicorn --bind 0.0.0.0:8080 --workers $WORKERS --threads $THREADS run:app"

    # ✅ Ensure Gunicorn is fully started before Locust runs
    echo "⏳ Waiting for Gunicorn to be ready..."
    until curl -sSf http://localhost:8080/api > /dev/null 2>&1; do
      sleep 2
    done
    echo "✅ Gunicorn is ready!"

    # Run Locust test for 30 seconds
    locust -f locustfile.py --headless -H http://localhost:8080 --users 1000 --spawn-rate 10 --run-time 300s --csv=locust_results --only-summary
    
    # Extract Locust metrics
    REQUESTS_PER_SEC=$(awk -F',' 'NR==2 {print $9}' locust_results_stats.csv)
    AVG_RESPONSE_TIME=$(awk -F',' 'NR==2 {print $5}' locust_results_stats.csv)
    MAX_RESPONSE_TIME=$(awk -F',' 'NR==2 {print $8}' locust_results_stats.csv)

    mv locust_results_stats.csv "locust_results_workers_${WORKERS}_threads_${THREADS}.csv"

    # Save results
    echo "$WORKERS,$THREADS,$REQUESTS_PER_SEC,$AVG_RESPONSE_TIME,$MAX_RESPONSE_TIME" >> $LOGFILE
  done
done

# Stop all services after testing
docker-compose -f docker-compose.yml down

echo "✅ Performance testing complete! Results saved in $LOGFILE"
