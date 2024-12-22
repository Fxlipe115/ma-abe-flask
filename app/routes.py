from attr import has
from flask import Blueprint, Flask, request, jsonify
from charm.toolbox.pairinggroup import PairingGroup, GT, G1, G2, ZR
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes, bytesToObject
from flask_restx import Api, Resource, fields
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import requests

from key_manager import KeyManager
from key_manager.hashicorp import HashiCorpVaultKeyManager
import re

blueprint = Blueprint('api', __name__, url_prefix='/api')
api = Api(blueprint, doc='/docs', version='1.0', title='MA-ABE API', description='A simple MA-ABE API')

group = PairingGroup('MNT224')
maabe = MaabeRW15(group)

# Global parameters and authorities
global_params = maabe.setup()
key_manager: KeyManager = HashiCorpVaultKeyManager()

setup_authority_model = api.model('SetupAuthority', {
    'authority_name': fields.String(required=True, description='Name of the authority')
})

@api.route('/setup_authority')
class SetupAuthority(Resource):
    @api.expect(setup_authority_model)
    def post(self):
        data = request.json
        authority_name = data['authority_name']
        authority_keys = maabe.authsetup(global_params, authority_name)

        public_key = objectToBytes(authority_keys[0], group).hex()
        secret_key = objectToBytes(authority_keys[1], group).hex()

        key_manager.store_key(f'{authority_name}_public_key', public_key)
        key_manager.store_key(f'{authority_name}_secret_key', secret_key)

        return jsonify({'status': 'success', 'authority_name': authority_name})


keygen_model = api.model('KeyGen', {
    'authority_name': fields.String(required=True, description='The name of the authority'),
    'attributes': fields.List(fields.String, required=True, description='List of attributes'),
    'user_id': fields.String(required=True, description='The user ID')
})

@api.route('/keygen')
class Keygen(Resource):
    @api.expect(keygen_model)
    def post(self):
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid input data'}), 400

        authority_name = data.get('authority_name')
        attributes = data.get('attributes')  # List of attributes to add
        user_id = data.get('user_id')

        if not authority_name or not attributes or not user_id:
            return jsonify({'error': 'Missing required parameters'}), 400

        try:
            secret_key = key_manager.retrieve_key(f'{authority_name}_secret_key')
        except requests.exceptions.ConnectionError as e:
            print("Vault Connection Error:", str(e))
            return jsonify({'error': 'Failed to connect to Vault'}), 500
        
        secret_keys = bytesToObject(bytes.fromhex(secret_key), group)

        existing_key = {}
        try:
            existing_key_hex = key_manager.retrieve_key(f'{user_id}_key')
            existing_key = bytesToObject(bytes.fromhex(existing_key_hex), group)
        except Exception as e:
            print("No existing key found in Vault for user:", user_id)
            print("Creating a new key")
        
        try:
            for attribute in attributes:
                user_key = maabe.keygen(global_params, secret_keys, user_id, attribute.upper())

                if 'keys' not in existing_key:
                    existing_key['keys'] = {}
                existing_key['keys'][attribute.upper()] = user_key

            if 'GID' not in existing_key:
                existing_key['GID'] = user_id

            serialized_key = objectToBytes(existing_key, group).hex()
            key_manager.store_key(f'{user_id}_key', serialized_key)
            return jsonify({'status': 'success', 'user_key': serialized_key})
        except Exception as e:
            print("Keygen Error:", str(e))
            return jsonify({'error': f"Key generation failed: {str(e)}"}), 500


encrypt_model = api.model('Encrypt', {
    'policy': fields.String(required=True, description='The encryption policy'),
    'payload': fields.String(required=True, description='The payload to encrypt')
})
@api.route('/encrypt')
class Encrypt(Resource):
    @api.expect(encrypt_model)
    def post(self):
        data = request.json
        if not data or 'policy' not in data or 'payload' not in data:
            return jsonify({'error': 'Missing required parameters: policy and payload'}), 400

        try:
            policy = data['policy']
            payload = data['payload']

            gt = group.random(GT)

            if gt == group.init(GT, 1):  # Identity element of GT
                raise ValueError("Computed GT is invalid (identity element).")


            # Retrieve public keys from Vault
            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            for authority_name in authority_names:
                public_key = key_manager.retrieve_key(f'{authority_name}_public_key')
                public_keys[authority_name] = bytesToObject(bytes.fromhex(public_key), group)

            encrypted_key = maabe.encrypt(global_params, public_keys, gt, policy)
            serialized_encrypted_key = objectToBytes(encrypted_key, group)

            # key_bytes = pickle.dumps(symmetric_key)
            symmetric_key = gt
            serialized_symmetric_key = objectToBytes(symmetric_key, group)

            # Hash and truncate the symmetric key to 32 bytes (256 bits) for AES encryption
            hashed_key = hashlib.sha256(serialized_symmetric_key).digest()

            # Encrypt the payload with AES
            aes_cipher = AES.new(hashed_key, AES.MODE_CBC)
            iv = aes_cipher.iv
            ciphertext = aes_cipher.encrypt(pad(payload.encode('utf-8'), AES.block_size))

            result = f"{ciphertext.hex()}:{serialized_encrypted_key.hex()}:{iv.hex()}"
            return jsonify({'result': result})
        except Exception as e:
            print("Encryption Error:", str(e))
            return jsonify({'error': f"Encryption failed: {str(e)}"}), 500


decrypt_model = api.model('Decrypt', {
    'user_id': fields.String(required=True, description='The user ID'),
    'payload': fields.String(required=True, description='The ciphertext to decrypt')
})
@api.route('/decrypt')
class Decrypt(Resource):
    @api.expect(decrypt_model)
    def post(self):
        data = request.json
        if not data or 'payload' not in data or 'user_id' not in data:
            return jsonify({'error': 'Missing required parameters: user_id, payload'}), 400
        
        user_id = data['user_id']
        payload = data['payload']

        try:
            try:
                serialized_keys_hex = key_manager.retrieve_key(f'{user_id}_key')
                serialized_keys = bytes.fromhex(serialized_keys_hex)
            except requests.exceptions.ConnectionError as e:
                print("Vault Connection Error:", str(e))
                return jsonify({'error': 'Failed to connect to Vault'}), 500
            except Exception as e:
                print("Key Retrieval Error:", str(e))
                return jsonify({'error': 'Failed to retrieve user keys from Vault'}), 500
            user_keys = bytesToObject(serialized_keys, group)

            # serialized_ciphertext = bytes.fromhex(data['ciphertext'])
            ciphertext_hex, encrypted_key_hex, iv_hex = payload.split(':')
            ciphertext = bytes.fromhex(ciphertext_hex)
            serialized_encrypted_key = bytes.fromhex(encrypted_key_hex)
            iv = bytes.fromhex(iv_hex)

            encrypted_key = bytesToObject(serialized_encrypted_key, group)
            symmetric_key = maabe.decrypt(global_params, user_keys, encrypted_key)

            serialized_symmetric_key = objectToBytes(symmetric_key, group)

            # Hash and truncate the symmetric key to 32 bytes (256 bits) for AES encryption
            hashed_key = hashlib.sha256(serialized_symmetric_key).digest()
            
            aes_cipher = AES.new(hashed_key, AES.MODE_CBC, iv=iv)
            unencrypted_payload = unpad(aes_cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            print(unencrypted_payload)

            # decoded_message_bytes = objectToBytes(message, group)

            # decoded_message = decoded_message_bytes.decode('utf-8')

            return jsonify({'decrypted_message': unencrypted_payload})
        except Exception as e:
            print("Decryption Error:", str(e))
            return jsonify({'error': f"Decryption failed: {str(e)}"}), 500

