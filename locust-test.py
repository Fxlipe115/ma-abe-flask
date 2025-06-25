import random
from locust import HttpUser, task, between
from locust.runners import STATE_STOPPING, STATE_STOPPED, STATE_CLEANUP
from locust import events
import json

class MyUser(HttpUser):
    wait_time = between(1, 2)

    def on_start(self):
        self.user_ids = []
        self.authorities = []
        self.setup_authorities()
        self.distribute_keys()

    def setup_authorities(self):
        for i in range(10):
            authority_name = f"authority_{i}"
            response = self.client.post("/api/setup_authority", json={"authority_name": authority_name})
            assert response.status_code == 200, f"Failed to setup authority {authority_name}"
            self.authorities.append(authority_name)

    def distribute_keys(self):
        for i in range(10):
            user_id = f"user_{i}"
            authority_name = f"authority_{i % 10}"
            attributes = ["attr1", "attr2", "attr3"]
            response = self.client.post(
                "/api/keygen",
                json={"authority_name": authority_name, "attributes": attributes, "user_id": user_id}
            )
            assert response.status_code == 200, f"Failed to distribute keys to {user_id}"
            self.user_ids.append(user_id)

    @task
    def encrypt_decrypt(self):
        user_id = random.choice(self.user_ids)
        policy = 'attr1@authority_0 AND attr2@authority_1'
        payload_data = "This is a test payload"

        # Encrypt the payload
        encrypt_response = self.client.post(
            "/api/encrypt",
            json={"policy": policy, "payload": payload_data}
        )
        assert encrypt_response.status_code == 200, f"Encryption failed: {encrypt_response.text}"
        result = encrypt_response.json().get("result")
        assert result, "No result returned for encryption"

        # Decrypt the payload
        decrypt_response = self.client.post(
            "/api/decrypt",
            json={"user_id": user_id, "payload": result}
        )
        assert decrypt_response.status_code == 200, f"Decryption failed: {decrypt_response.text}"
        decrypted_message = decrypt_response.json().get("decrypted_message")
        assert decrypted_message == payload_data, "Decrypted message does not match original payload"

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    user = MyUser(environment)
    user.on_start()

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    if environment.runner.state in [STATE_STOPPING, STATE_STOPPED, STATE_CLEANUP]:
        print("Test stopped")
