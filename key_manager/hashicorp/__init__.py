import os

import hvac
from key_manager import KeyManager


class HashiCorpVaultKeyManager(KeyManager):
    def __init__(self):
        vault_url = os.getenv('VAULT_URL', 'http://127.0.0.1:8200')
        vault_token = os.getenv('VAULT_TOKEN', 'myroot')
        self.client = hvac.Client(url=vault_url, token=vault_token)

    def store_key(self, key_name, key):
        self.client.secrets.kv.v2.create_or_update_secret(
            path=key_name,
            secret={'key': key}
        )

    def retrieve_key(self, key_name):
        response = self.client.secrets.kv.v2.read_secret_version(path=key_name)
        return response['data']['data']['key']