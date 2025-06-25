from collections import defaultdict
from email.policy import default
import os
from attr import has
from flask import Blueprint, Flask, request, jsonify
from charm.toolbox.pairinggroup import PairingGroup, GT, G1, G2, ZR
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction, SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from flask_restx import Api, Resource, fields
import hashlib
import requests
import threading

from flask import send_file, make_response
from werkzeug.datastructures import FileStorage
import io


from key_manager import KeyManager
import re

from key_manager.redis import RedisKeyManager

# decrypt_lock = threading.Lock()

blueprint = Blueprint('api', __name__, url_prefix='/api')
api = Api(blueprint, doc='/docs', version='1.0', title='MA-ABE API', description='A simple MA-ABE API')

key_manager: KeyManager = RedisKeyManager(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=int(os.getenv('REDIS_DB', 0))
)


# Global variables for in-memory storage
_global_params = None

def get_maabe():
    global _global_params

    group = PairingGroup('MNT224')
    maabe = MaabeRW15(group)

    if _global_params is not None:
        return maabe, group, _global_params  # Cached in memory

    try:
        # Fetch from Redis (Shared across workers)
        stored_params = key_manager.retrieve_key('global_params')

        if stored_params:
            global_params = bytesToObject(stored_params, group)
            setup_with_lambdas = maabe.setup()
            global_params['H'] = setup_with_lambdas['H']
            global_params['F'] = setup_with_lambdas['F']
            _global_params = global_params  # Store in memory
            print("✅ Loaded global_params from Redis")
            return maabe, group, global_params
    except Exception as e:
        print("❌ Redis error:", str(e))

    # Fallback: Generate new parameters (should not happen if sidecar works)
    print("⚠️ WARNING: Generating new global_params (Redis unavailable)")
    global_params = maabe.setup()
    key_manager.store_key('global_params', objectToBytes(global_params, group))  # Store back in Redis
    _global_params = global_params

    return maabe, group, global_params


setup_authority_model = api.model('SetupAuthority', {
    'authority_name': fields.String(required=True, description='Name of the authority')
})

# user_locks = defaultdict(threading.Lock)

# def get_user_lock(user_id: str):
#     return user_locks[user_id]

@api.route('/setup_authority')
class SetupAuthority(Resource):
    @api.expect(setup_authority_model)
    def post(self):
        maabe, group, global_params = get_maabe()

        data = request.json
        authority_name = data['authority_name']
        authority_keys = maabe.authsetup(global_params, authority_name)

        public_key = objectToBytes(authority_keys[0], group)
        secret_key = objectToBytes(authority_keys[1], group)

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
        maabe, group, global_params = get_maabe()

        data = request.json
        if not data:
            return jsonify({'error': 'Invalid input data'}), 400

        authority_name = data.get('authority_name')
        attributes = data.get('attributes')  # List of attributes to add
        user_id = data.get('user_id')

        if not authority_name or not attributes or not user_id:
            return jsonify({'error': 'Missing required parameters'}), 400

        # try:
        #     secret_key = key_manager.retrieve_key(f'{authority_name}_secret_key')
        # except requests.exceptions.ConnectionError as e:
        #     print("Vault Connection Error:", str(e))
        #     return jsonify({'error': 'Failed to connect to Vault'}), 500
        
        # secret_keys = bytesToObject(secret_key, group)

        # user_lock = get_user_lock(user_id)
        # with user_lock:
        existing_key = {}
        try:
            # existing_key_hex = key_manager.retrieve_key(f'{user_id}_key')
            secret_key, existing_key_hex = key_manager.retrieve_keys([f'{authority_name}_secret_key', f'{user_id}_key'])

            secret_keys = bytesToObject(secret_key, group)
            existing_key = bytesToObject(existing_key_hex, group)
        except Exception as e:
            print(f"Creating a new key for user: {user_id}")
        
        try:
            for attribute in attributes:
                user_key = maabe.keygen(global_params, secret_keys, user_id, attribute.upper())

                if 'keys' not in existing_key:
                    existing_key['keys'] = {}
                existing_key['keys'][attribute.upper()] = user_key

            if 'GID' not in existing_key:
                existing_key['GID'] = user_id

            serialized_key = objectToBytes(existing_key, group)
            key_manager.store_key(f'{user_id}_key', serialized_key)
            return jsonify({'status': 'success', 'user_key': serialized_key.hex()})
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
        maabe, group, global_params = get_maabe()
        a = str(group.Pairing)

        data = request.json
        if not data or 'policy' not in data or 'payload' not in data:
            return jsonify({'error': 'Missing required parameters: policy and payload'}), 400

        try:
            policy: str = data['policy']
            payload: str = data['payload']

            gt = group.random(GT, seed=1)
            # hashed = hashlib.sha256(payload.encode()).digest()
            # gt = group.hash(hashed, GT)

            if gt == group.init(GT, 1):  # Identity element of GT
                raise ValueError("Computed GT is invalid (identity element).")


            # Retrieve public keys from Vault
            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            for authority_name in authority_names:
                public_key = key_manager.retrieve_key(f'{authority_name}_public_key')
                public_keys[authority_name] = bytesToObject(public_key, group)

            encrypted_key = maabe.encrypt(global_params, public_keys, gt, policy)
            serialized_encrypted_key = objectToBytes(encrypted_key, group)

            # key_bytes = pickle.dumps(symmetric_key)
            symmetric_key = gt
            print("GT Before Encryption:", objectToBytes(gt, group))
            
            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            encrypted_result = symcrypt.encrypt(payload)

            encrypted_result_hex = str.encode(encrypted_result).hex()
            result = f"{encrypted_result_hex}:{serialized_encrypted_key.hex()}"
            return jsonify({'result': result})
        except Exception as e:
            print("Encryption Error:", str(e))
            return jsonify({'error': "Encryption failed"}), 500


decrypt_model = api.model('Decrypt', {
    'user_id': fields.String(required=True, description='The user ID'),
    'payload': fields.String(required=True, description='The ciphertext to decrypt')
})
@api.route('/decrypt')
class Decrypt(Resource):
    @api.expect(decrypt_model)
    def post(self):
        maabe, group, global_params = get_maabe()
        a = str(group.Pairing)

        data = request.json
        if not data or 'payload' not in data or 'user_id' not in data:
            return jsonify({'error': 'Missing required parameters: user_id, payload'}), 400
        
        user_id = data['user_id']
        payload = data['payload']

        try:
            try:
                serialized_keys_hex = key_manager.retrieve_key(f'{user_id}_key')
                serialized_keys = serialized_keys_hex
            except requests.exceptions.ConnectionError as e:
                print("Vault Connection Error:", str(e))
                return jsonify({'error': 'Failed to connect to Vault'}), 500
            except Exception as e:
                print("Key Retrieval Error:", str(e))
                return jsonify({'error': 'Failed to retrieve user keys from Vault'}), 500
            user_keys = bytesToObject(serialized_keys, group)

            ciphertext_hex, encrypted_key_hex = payload.split(':')
            ciphertext = bytes.fromhex(ciphertext_hex)
            serialized_encrypted_key = bytes.fromhex(encrypted_key_hex)

            encrypted_key = bytesToObject(serialized_encrypted_key, group)
            # with decrypt_lock:
            symmetric_key = maabe.decrypt(global_params, user_keys, encrypted_key)

            print("GT After Decryption:", objectToBytes(symmetric_key, group))
            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            unencrypted_payload = symcrypt.decrypt(ciphertext.decode())

            return jsonify({'decrypted_message': unencrypted_payload.decode()})
        except Exception as e:
            print("Decryption Error:", repr(e))
            print(f"CIPHERTEXT: {ciphertext_hex}\nUSER_ID: {user_id}")
            return {'error': f"Decryption failed: {str(e)}"}, 500


encrypt_parser = api.parser()
encrypt_parser.add_argument('policy', type=str, required=True, help='The encryption policy', location='form')
encrypt_parser.add_argument('payload', type=FileStorage, required=True, help='The file to encrypt', location='files')

@api.route('/encrypt_file')
class EncryptFile(Resource):
    # Use o parser em vez do model para documentação e validação
    @api.expect(encrypt_parser)
    def post(self):
        maabe, group, global_params = get_maabe()
        args = encrypt_parser.parse_args()

        try:
            policy: str = args['policy']
            payload_file: FileStorage = args['payload']
            payload_bytes: bytes = payload_file.read() # Ler o arquivo como bytes

            # A lógica de geração de chave simétrica e ABE permanece a mesma
            gt = group.random(GT, seed=1) # Usar um seed aqui é apenas para teste, use group.random(GT) em produção
            
            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            # Recupera as chaves públicas necessárias
            public_key_names = [f'{name}_public_key' for name in authority_names]
            retrieved_keys = key_manager.retrieve_keys(public_key_names)
            
            for name, key_bytes in zip(authority_names, retrieved_keys):
                if key_bytes:
                    public_keys[name] = bytesToObject(key_bytes, group)
                else:
                    return jsonify({'error': f"Public key for authority '{name}' not found"}), 404

            # Criptografa a chave simétrica (gt) com a política ABE
            encrypted_key = maabe.encrypt(global_params, public_keys, gt, policy)
            serialized_encrypted_key = objectToBytes(encrypted_key, group)

            # Criptografa o payload do arquivo com a chave simétrica
            symcrypt = SymmetricCryptoAbstraction(extractor(gt))
            encrypted_payload_bytes = symcrypt.encrypt(payload_bytes)

            # Crie uma resposta binária
            response = make_response(encrypted_payload_bytes)
            response.headers.set('Content-Type', 'application/octet-stream')
            response.headers.set(
                'Content-Disposition', 'attachment', filename=f'encrypted_{payload_file.filename}'
            )
            # Envie a chave ABE em um cabeçalho personalizado
            response.headers.set('X-Encryption-Key', serialized_encrypted_key.hex())

            return response

        except Exception as e:
            print("Encryption Error:", str(e))
            # Garante que o traceback seja impresso para depuração
            import traceback
            traceback.print_exc()
            return {'error': "Encryption failed"}, 500

decrypt_parser = api.parser()
decrypt_parser.add_argument('user_id', type=str, required=True, help='The user ID', location='form')
decrypt_parser.add_argument('encrypted_key_hex', type=str, required=True, help='The ABE encrypted key (in hex)', location='form')
decrypt_parser.add_argument('ciphertext_file', type=FileStorage, required=True, help='The encrypted file', location='files')

@api.route('/decrypt_file')
class DecryptFile(Resource):
    @api.expect(decrypt_parser)
    def post(self):
        maabe, group, global_params = get_maabe()
        args = decrypt_parser.parse_args()

        try:
            user_id = args['user_id']
            encrypted_key_hex = args['encrypted_key_hex']
            ciphertext_file: FileStorage = args['ciphertext_file']
            
            # Ler o conteúdo do arquivo criptografado
            ciphertext_bytes = ciphertext_file.read()

            # Recuperar a chave do usuário
            serialized_keys = key_manager.retrieve_key(f'{user_id}_key')
            if not serialized_keys:
                return jsonify({'error': 'User key not found'}), 404
            user_keys = bytesToObject(serialized_keys, group)
            
            # Deserializar a chave ABE
            serialized_encrypted_key = bytes.fromhex(encrypted_key_hex)
            encrypted_key = bytesToObject(serialized_encrypted_key, group)

            # Descriptografar para obter a chave simétrica
            symmetric_key = maabe.decrypt(global_params, user_keys, encrypted_key)
            if symmetric_key is False:
                return {'error': 'Decryption failed: Policy not satisfied or invalid key.'}, 403

            # Usar a chave simétrica para descriptografar o arquivo
            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            decrypted_payload_bytes = symcrypt.decrypt(ciphertext_bytes)
            
            # Enviar o arquivo descriptografado como um download
            return send_file(
                io.BytesIO(decrypted_payload_bytes),
                as_attachment=True,
                download_name=f'decrypted_{ciphertext_file.filename}',
                mimetype='application/octet-stream'
            )

        except Exception as e:
            print("Decryption Error:", repr(e))
            import traceback
            traceback.print_exc()
            return {'error': f"Decryption failed: {str(e)}"}, 500
