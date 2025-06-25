#!/bin/bash

# Ensure script stops on error
set -e

RUN_TIME=30m

# Phase 1: Optimize Workers & Threads
# This phase tests different worker and thread counts while keeping payload and users fixed.
# WORKERS_LIST=(1 5 10 15 20 25) 
# THREADS_LIST=(1 8 12 16 24 32)
# USERS_LIST=(100) 
# PAYLOAD_SIZE_LIST=(1024)
# NUMBER_OF_POLICIES_LIST=(1)

# Phase 2: Optimize Payload Sizes
# This phase tests different payload sizes while keeping the best workers/threads and users fixed.
WORKERS_LIST=(25)
THREADS_LIST=(1)
PAYLOAD_SIZE_LIST=(1024 4096 16384 32768 65536 262144)
USERS_LIST=(100)  
NUMBER_OF_POLICIES_LIST=(1)

# Phase 3: Optimize User Loads
# This phase tests different user loads while keeping the best workers/threads and payload size fixed.
# WORKERS_LIST=(25) 
# THREADS_LIST=(1) 
# PAYLOAD_SIZE_LIST=(65536 262144)  
# USERS_LIST=(10 50 100 250 500 1000)  
# NUMBER_OF_POLICIES_LIST=(1) 

# Phase 4: Optimize Number of Keys
# This phase tests different number of keys while keeping the best workers/threads, payload size, and user loads fixed.
# WORKERS_LIST=(25)  
# THREADS_LIST=(1)  
# PAYLOAD_SIZE_LIST=(65536)  
# USERS_LIST=(100)  
# NUMBER_OF_POLICIES_LIST=(1 2 3 4 5 6 7 8 9 10)  




declare -a test_cases=()

# Generate 4-tuples and store them in the array
for WORKERS in "${WORKERS_LIST[@]}"; do
  for THREADS in "${THREADS_LIST[@]}"; do
    for USERS in "${USERS_LIST[@]}"; do
      for PAYLOAD_SIZE in "${PAYLOAD_SIZE_LIST[@]}"; do
        for NUMBER_OF_POLICIES in "${NUMBER_OF_POLICIES_LIST[@]}"; do
          test_cases+=("$WORKERS,$THREADS,$USERS,$PAYLOAD_SIZE,$NUMBER_OF_POLICIES")
        done
      done
    done
  done
done

# Shuffle the array using `shuf`
shuffled_test_cases=($(printf "%s\n" "${test_cases[@]}" | shuf))


# echo "Shuffled tuples: ${shuffled_test_cases[@]}"

# Create a timestamped folder
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
# RESULTS_DIR="test_results/${TIMESTAMP}U${USERS}R${SPAWN_RATE}T${RUN_TIME}"
RESULTS_DIR="test_results/${TIMESTAMP}T${RUN_TIME}"
mkdir -p "$RESULTS_DIR"

cleanup() {
    if [[ -n "$LOCUST_PID" && -e /proc/$LOCUST_PID ]]; then
        echo "🛑 Stopping Locust gracefully..."
        kill -SIGTERM "$LOCUST_PID"
        wait "$LOCUST_PID" || true
        sleep 5  # Allow time for Locust to exit cleanly
    fi
}

# Handle script termination (Ctrl+C)
trap cleanup SIGINT SIGTERM

echo "⏳ Stopping existing Web service..."
docker compose -f docker-compose.yml down --remove-orphans || true

TEST_TOTAL=${#shuffled_test_cases[@]}
TEST_INDEX=0

for test_case in "${shuffled_test_cases[@]}"; do
  IFS="," read -r WORKERS THREADS USERS PAYLOAD_SIZE NUMBER_OF_POLICIES <<< "$test_case"

  # Start Gunicorn with the new settings inside the container
  echo "🚀 Starting Gunicorn with $WORKERS workers and $THREADS threads..."
  WORKERS="$WORKERS" THREADS="$THREADS" docker compose -f docker-compose.yml up -d

  # ✅ Ensure Gunicorn is fully started before Locust runs
  echo "⏳ Waiting for Gunicorn to be ready (locally)..."
  until curl -sSf http://localhost:8080/api > /dev/null 2>&1; do
    sleep 2
  done
  echo "✅ Gunicorn is ready!"

  TEST_INDEX=$((TEST_INDEX + 1))
  echo "🔹 Test $TEST_INDEX/$TEST_TOTAL"
  echo "🔹 Testing Workers=$WORKERS, Threads=$THREADS"
  echo "🔹 Testing Users=$USERS, Payload=$PAYLOAD_SIZE, Policies=$NUMBER_OF_POLICIES"

  # Run Locust tests
  echo "🏃 Running Locust for Workers=$WORKERS, Threads=$THREADS, Users=$USERS..."
  LOCUST_CSV_PREFIX="$RESULTS_DIR/locust_results_workers_${WORKERS}_threads_${THREADS}_users_${USERS}_payload_${PAYLOAD_SIZE}_policies_${NUMBER_OF_POLICIES}"\

  PAYLOAD_SIZE=$PAYLOAD_SIZE NUMBER_OF_POLICIES=$NUMBER_OF_POLICIES locust -f locustfile.py --headless -H http://localhost:8080 --users $USERS --spawn-rate $USERS --run-time $RUN_TIME --csv="$LOCUST_CSV_PREFIX" --only-summary --csv-full-history || true &
  LOCUST_PID=$!

  wait $LOCUST_PID

  cleanup

  echo "⏳ Stopping existing Web service..."
  docker compose -f docker-compose.yml down --remove-orphans || true
done

# Stop all services after testing
docker compose -f docker-compose.yml down

echo "✅ Performance testing complete! Results saved in $RESULTS_DIR"

