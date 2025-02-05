import csv
from dataclasses import dataclass
from datetime import datetime
from operator import ge
import string
from typing import Dict, List
from locust import HttpUser, events, task, between
from locust.exception import StopUser
import random
from pprint import pprint
import difflib

@dataclass
class EncryptedPayload:
    plain_text: str
    encrypted_text: str
    policy: str

authorities = []
users: Dict[str, List[str]] = {}
encrypted_payloads: Dict[str, List[EncryptedPayload]] = {}

authority_quantity = 0
def generate_authority_name():
    global authority_quantity
    name = f"AUTHORITY{authority_quantity}"
    authority_quantity += 1
    return name

user_quantity = 0
def generate_user_id():
    global user_quantity
    name = f"USER{user_quantity}"
    user_quantity += 1
    return name

attribute_quantity = 0
def generate_attribute_name():
    global attribute_quantity
    name = f"ATTRIBUTE{attribute_quantity}"
    attribute_quantity += 1
    return name

def generate_attribute_authority_pair(authority = None):
    attribute = generate_attribute_name()
    authority = authority if authority else random.choice(authorities)
    return f"{attribute}@{authority}"

def generate_random_payload(size: int = 1024) -> str:
    """Generate a random string payload of the given size."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

class User(HttpUser):
    weight = 90
    wait_time = between(.1, .5)
    encrypted_payload = None

    def on_start(self):
        self.create_user()

    @task(1)
    def create_user(self):
        if len(users) < 1000:
            user_id = generate_user_id()
            users[user_id] = []

    @task(10)
    def encrypt(self):
        users_with_attributes = {user_id: attributes for user_id, attributes in users.items() if len(attributes) > 0}
        if len(users_with_attributes) == 0:
            return
        user_id = random.choice(list(users_with_attributes.keys()))
        attributes = users_with_attributes[user_id]
        sampled_attributes = random.sample(attributes, random.randint(1, len(attributes)))
        policy = ' AND '.join(sampled_attributes)
        payload = generate_random_payload(2048)
        response = self.client.post("/api/encrypt", json={
            "policy": policy,
            "payload": payload
        })
        
        if response.status_code == 200:
            encrypted_text = response.json().get('result')
            encrypted_payload = EncryptedPayload(
                plain_text=payload, 
                encrypted_text=encrypted_text, 
                policy=policy
                )
            if user_id not in encrypted_payloads:
                encrypted_payloads[user_id] = [encrypted_payload]
            encrypted_payloads[user_id].append(encrypted_payload)
    
    @task(10)
    def decrypt(self):
        if len(encrypted_payloads) == 0:
            return
        user_id = random.choice(list(encrypted_payloads.keys()))
        payloads = encrypted_payloads[user_id]
        payload = random.choice(payloads)
        with self.client.post("/api/decrypt", json={
            "user_id": user_id,
            "payload": payload.encrypted_text
        },
        catch_response=True) as response:
            if response.status_code == 200:
                decrypted_text = response.json().get('decrypted_message')
                try:
                    assert decrypted_text == payload.plain_text
                except AssertionError as e:
                    # print(f"Decrypted text does not match the original text: {e}")
                    # print(f"Decrypted text: {decrypted_text}")
                    # print(f"Original text: {payload.plain_text}")
                    diff = difflib.ndiff([payload.plain_text], [decrypted_text])
                    diff_text = '\n'.join(diff)
                    response.failure(f"Decrypted text does not match the original text:\n{diff_text}")
            if response.status_code == 500:
                error = response.json().get('error')
                response.failure(f"{error}")


class Authority(HttpUser):
    wait_time = between(1, 5)
    weight = 50
    # fixed_count = 10
    def on_start(self):
        self.setup_authority()

    @task(1)
    def setup_authority(self):
        if len(authorities) < 10:
            authority_name = generate_authority_name()
            response = self.client.post("/api/setup_authority", json={"authority_name": authority_name})
            if response.status_code == 200:
                authorities.append(authority_name)

    @task(50)
    def keygen(self):
        if len(authorities) == 0:
            return
        authority_name = random.choice(list(authorities))
        users_with_no_attributes = {user_id: attributes for user_id, attributes in users.items() if len(attributes) == 0}
        if len(users_with_no_attributes) > 0:
            user_id = random.choice(list(users_with_no_attributes.keys()))
        else: 
            user_id = random.choice(list(users.keys()))
        attributes = [generate_attribute_authority_pair(authority_name) for _ in range(random.randint(1, 5))]
        response = self.client.post("/api/keygen", json={
            "authority_name": authority_name,
            "attributes": list(attributes),
            "user_id": user_id
        })
        if response.status_code == 200:
            users[user_id] = list(set(users[user_id] + attributes))

@events.quitting.add_listener
def _(environment, **_kwargs):
    print("Quitting")
    pprint(users)
    pprint(authorities)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'encrypted_payloads_{timestamp}.csv'
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['user_id', 'plain_text', 'encrypted_text', 'policy'])
        for user_id, payloads in encrypted_payloads.items():
            for payload in payloads:
                writer.writerow([user_id, payload.plain_text, payload.encrypted_text, payload.policy])