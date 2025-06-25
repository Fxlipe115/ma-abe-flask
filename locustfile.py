from calendar import c
from collections import defaultdict, deque
import csv
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import context
import time
import json
from operator import ge
import os
import string
from typing import Dict, List
from flask import request
from locust import HttpUser, events, task, between
from locust.exception import StopUser
import random
import difflib
import threading
import secrets
from http.client import RemoteDisconnected
import redis
from functools import wraps
import locust.stats

csv_log_prefix = ''

def ignore_remote_disconnected(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RemoteDisconnected:
            pass
    return wrapper


@events.test_start.add_listener
def on_test_start(environment, **_kwargs):
    global csv_log_prefix
    csv_log_prefix = environment.parsed_options.csv_prefix
    with open(f"{csv_log_prefix}_detailed.csv", 'w') as f:
        log_writer = csv.writer(f)
        log_writer.writerow([
            'Request Type',
            'Name',
            'Start Time',
            'Response Time (ms)',
            # 'Context',
            'Response Length',
            'Payload Size ',
            'Cryptographed Payload Size (bytes)',
            'Cryptographed Key Size (bytes)',
            'User Key Size (bytes)',
            'User Attributes',
            'Status Code',
            # 'Response Text',
            'Exception'
        ])

    redis_client = redis.StrictRedis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=int(os.getenv('REDIS_DB', 0)),
        decode_responses=True
    )
    redis_client.select(0)
    redis_client.flushdb()
    print("Redis DB 0 cleaned before starting the test.")


@events.request.add_listener
def my_request_handler(request_type, name, response_time, response_length, response,
                       context, exception, start_time, url, **kwargs):
    with open(f"{csv_log_prefix}_detailed.csv", 'a') as f:
        log_writer = csv.writer(f)
        log_writer.writerow([
            request_type,
            name,
            start_time,
            response_time,
            # context,
            response_length,
            context.get('payload_size', ''),
            context.get('cryptographed_payload_size', ''),
            context.get('cryptographed_key_size', ''),
            context.get('user_key_size', ''),
            context.get('user_attributes', ''),
            response.status_code,
            # response.text,
            exception
        ])
        
@dataclass
class EncryptedPayload:
    plain_text: str
    encrypted_text: str
    policy: str

authorities = []
users_lock = threading.Lock()
user_lock: Dict[str, threading.Lock] = defaultdict(threading.Lock)
users: Dict[str, List[str]] = defaultdict(list)
user_ids_lock = threading.Lock()
user_ids = deque()
encrypted_payloads: Dict[str, List[EncryptedPayload]] = defaultdict(list)

authority_quantity_lock = threading.Lock()
authority_quantity = 0
def generate_authority_name():
    global authority_quantity
    with authority_quantity_lock:
        name = f"AUTHORITY{authority_quantity:04}"
        authority_quantity += 1
    return name

user_quantity_lock = threading.Lock()
user_quantity = 0
def generate_user_id():
    global user_quantity
    with user_quantity_lock:
        name = f"USER{user_quantity:04}"
        user_quantity += 1
    return name

attribute_quantity_lock = threading.Lock()
attribute_quantity = 0
def generate_attribute_name():
    global attribute_quantity
    with attribute_quantity_lock:
        name = f"ATTRIBUTE{attribute_quantity:04}"
        attribute_quantity += 1
    return name

def generate_attribute_authority_pair(authority = None):
    attribute = generate_attribute_name()
    authority = authority if authority else random.choice(authorities)
    return f"{attribute}@{authority}"

def generate_random_payload(size: int = 1024) -> str:
    """Generate a random string payload of the given size."""
    return secrets.token_hex(size)

class User(HttpUser):
    weight = 4
    wait_time = between(1, 5)
    encrypted_payload = None

    def on_start(self):
        self.user_id = generate_user_id()
        users[self.user_id] = []
        user_lock[self.user_id] = threading.Lock()
        user_ids.append(self.user_id)

    # @task(10)
    # def encrypt(self):
    #     user_id = self.user_id
    #     attributes = users[user_id]
    #     number_of_policies = int(os.getenv('NUMBER_OF_POLICIES', 1))
    #     if len(attributes) < number_of_policies:
    #         return
        
    #     sampled_attributes = random.sample(attributes, number_of_policies)
    #     policy = ' AND '.join(sampled_attributes)
    #     payload = generate_random_payload(int(os.getenv('PAYLOAD_SIZE', 1024)))

    #     try:
    #         with self.client.post("/api/encrypt", 
    #         json={
    #             "policy": policy,
    #             "payload": payload
    #         },
    #         context = {
    #             "user_id": user_id,
    #             "policy": policy,
    #             "payload": payload
    #         },
    #         catch_response=True) as response:
    #             elapsed_time = response.elapsed.total_seconds() * 1000
    #             response.request_meta['response_time'] = elapsed_time
    #             if response.status_code == 200:
    #                 encrypted_text = response.json().get('result')
    #                 encrypted_payload = EncryptedPayload(
    #                     plain_text=payload, 
    #                     encrypted_text=encrypted_text, 
    #                     policy=policy
    #                     )
    #                 cryptographed_payload, cryptographed_key = encrypted_text.split(':')
    #                 context = response.request_meta['context']
    #                 context['payload_size'] = int(len(payload) // 2)
    #                 context['cryptographed_payload_size'] = int(len(cryptographed_payload) // 2)
    #                 context['cryptographed_key_size'] = int(len(cryptographed_key) // 2)
    #                 if user_id not in encrypted_payloads:
    #                     encrypted_payloads[user_id] = [encrypted_payload]
    #                 encrypted_payloads[user_id].append(encrypted_payload)
    #             elif response.status_code == 500:
    #                 code = response.status_code
    #                 error = response.json().get('error')
    #                 response.failure(f"{code}: {error}")
    #     except RemoteDisconnected:
    #         pass
    
    # @task(10)
    # def decrypt(self):
    #     if len(encrypted_payloads) == 0:
    #         return
    #     user_id = self.user_id
    #     if user_id not in encrypted_payloads or len(encrypted_payloads[user_id]) == 0:
    #         return
    #     payloads = encrypted_payloads[user_id]
    #     payload = random.choice(payloads)

    #     with self.client.post("/api/decrypt", 
    #     json={
    #         "user_id": user_id,
    #         "payload": payload.encrypted_text
    #     },
    #     context = {
    #         "user_id": user_id,
    #         "payload": payload.encrypted_text
    #     },
    #     catch_response=True) as response:
    #         elapsed_time = response.elapsed.total_seconds() * 1000
    #         response.request_meta['response_time'] = elapsed_time
    #         if response.status_code == 200:
    #             decrypted_text = response.json().get('decrypted_message')
    #             cryptographed_payload, cryptographed_key = payload.encrypted_text.split(':')
    #             context = response.request_meta['context']
    #             context['payload_size'] = int(len(decrypted_text) // 2)
    #             context['cryptographed_payload_size'] = int(len(cryptographed_payload) // 2)
    #             context['cryptographed_key_size'] = int(len(cryptographed_key) // 2)
    #             try:
    #                 assert decrypted_text == payload.plain_text
    #             except AssertionError as e:
    #                 diff = difflib.ndiff([payload.plain_text], [decrypted_text])
    #                 diff_text = '\n'.join(diff)
    #                 response.failure(f"Decrypted text does not match the original text:\n{diff_text}")
    #         if response.status_code == 500:
    #             code = response.status_code
    #             error_text = response.json().get('error')
    #             if not error_text:
    #                 error_text = response.text

    #             response.failure(f"{code}: {error_text}")

    @task(10)
    def do_nothing(self):
        pass


class Authority(HttpUser):
    wait_time = between(1, 5)
    weight = 1
    def on_start(self):
        self.authority_name = generate_authority_name()
        response = self.client.post("/api/setup_authority", 
        json= {
            "authority_name": self.authority_name
        },
        context= {
            "authority_name": self.authority_name
        })
        if response.status_code == 200:
            authorities.append(self.authority_name)
        else:
            print(response.text)
            raise StopUser()
        
        self.attributes = [f"ATTRIBUTE{idx:04}@{self.authority_name}" for idx in range(100)]

    @task(50)
    def keygen(self):
        if len(authorities) == 0:
            return
        authority_name = self.authority_name
        if len(user_ids) == 0:
            return
        user_id = user_ids[0]
        user_ids.rotate(-1)
        max_attributes = int(os.getenv('MAX_ATTRIBUTES', 100))
        if len(users[user_id]) > max_attributes:
            return
        attributes = random.sample(self.attributes, random.randint(1, 1))

        with self.client.post("/api/keygen", json={
            "authority_name": authority_name,
            "attributes": list(attributes),
            "user_id": user_id
        },
        context = {
            "authority_name": authority_name,
            "attributes": attributes,
            "user_id": user_id
        }, catch_response=True) as response:
            if response.status_code == 200:
                with user_lock[user_id]:
                    users[user_id] = list(set(users[user_id] + attributes))
                context = response.request_meta['context']
                context['user_key_size'] = int(len(response.json().get('user_key')) // 2)
                context['user_attributes'] = len(users[user_id])

# @events.quitting.add_listener
# def _(environment, **_kwargs):
#     timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#     results_dir = os.path.join('results', timestamp)
#     os.makedirs(results_dir, exist_ok=True)
    
#     encrypted_payloads_filename = os.path.join(results_dir, 'encrypted_payloads.csv')
#     with open(encrypted_payloads_filename, mode='w', newline='') as file:
#         writer = csv.writer(file)
#         writer.writerow(['user_id', 'plain_text', 'encrypted_text', 'policy'])
#         for user_id, payloads in encrypted_payloads.items():
#             for payload in payloads:
#                 writer.writerow([user_id, payload.plain_text, payload.encrypted_text, payload.policy])
    
#     stats_filename = os.path.join(results_dir, 'request_stats.csv')
#     with open(stats_filename, mode='w', newline='') as stats_file:
#         stats_writer = csv.writer(stats_file)
#         stats_writer.writerow(['Method', 'Name', 'Requests', 'Failures', 'Median Response Time', 'Average Response Time', 'Min Response Time', 'Max Response Time', 'Average Content Size', 'Requests Per Second'])
        
#         for stat in environment.stats.entries.values():
#             stats_writer.writerow([
#                 stat.method,
#                 stat.name,
#                 stat.num_requests,
#                 stat.num_failures,
#                 stat.median_response_time,
#                 stat.avg_response_time,
#                 stat.min_response_time,
#                 stat.max_response_time,
#                 stat.avg_content_length,
#                 stat.total_rps
#             ])
        
#         # Write aggregated stats
#         total_stats = environment.stats.total
#         stats_writer.writerow([
#             'Total',
#             '',
#             total_stats.num_requests,
#             total_stats.num_failures,
#             total_stats.median_response_time,
#             total_stats.avg_response_time,
#             total_stats.min_response_time,
#             total_stats.max_response_time,
#             total_stats.avg_content_length,
#             total_stats.total_rps
#         ])

#     json_filename = os.path.join(results_dir, 'data.json')
#     data = {
#         'users': users,
#         'authorities': authorities
#     }
#     with open(json_filename, 'w') as json_file:
#         json.dump(data, json_file, indent=2)


class LockMonitor(threading.Thread):
    def __init__(self, interval=1.0):
        super().__init__()
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            time.sleep(self.interval)
            active_locks = sum(1 for lock in user_lock.values() if lock.locked())
            print(f"Active Locks: {active_locks}")

    def stop(self):
        self.running = False
lock_monitor = LockMonitor()
# lock_monitor.start()
