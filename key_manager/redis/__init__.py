import redis
import hiredis
from key_manager import KeyManager

class RedisKeyManager(KeyManager):
    def __init__(self, host='localhost', port=6379, db=0):
        self.client = redis.StrictRedis(
            host=host, 
            port=port, 
            db=db, 
            decode_responses=True
        )

    def store_key(self, key_name, key):
        if key_name == "global_params":
            self.client.select(1)
        else:
            self.client.select(0)
        self.client.set(key_name, key)

    def retrieve_key(self, key_name):
        if key_name == "global_params":
            self.client.select(1)
        else:
            self.client.select(0)
        key = self.client.get(key_name)
        if key is None:
            raise KeyError(f'Key {key_name} not found')
        else:
            return key
        
    def retrieve_keys(self, key_names):
        self.client.select(0)
        keys = self.client.mget(key_names)
        return keys