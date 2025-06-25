import os
import time
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes
import redis

# Redis connection
redis_client = redis.StrictRedis(
    host=os.getenv('REDIS_HOST', 'redis'),  # Use the Redis service name in Docker
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=int(os.getenv('REDIS_DB', 0)),
    decode_responses=False
)

def initialize_global_params():
    print("Initializing Global Parameters in Redis...")
    
    group = PairingGroup('MNT224')
    maabe = MaabeRW15(group)
    global_params = maabe.setup()

    params_without_lambdas = {k: v for k, v in global_params.items() if k not in ["H", "F"]}

    # Convert to bytes
    serialized_params = objectToBytes(params_without_lambdas, group)

    # Store in Redis
    redis_client.select(1)
    redis_client.set('global_params', serialized_params)

    print("✅ Global parameters stored in Redis!")

if __name__ == "__main__":
    # Wait for Redis to be ready
    while True:
        try:
            redis_client.ping()
            break
        except redis.exceptions.ConnectionError:
            print("Waiting for Redis...")
            time.sleep(1)

    initialize_global_params()
