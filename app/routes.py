from flask import Blueprint, request, jsonify
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes, bytesToObject

main = Blueprint('main', __name__)

# Initialize MA-ABE
group = PairingGroup('MNT224')
maabe = MaabeRW15(group)

# Global parameters and authorities
global_params = maabe.setup()
authorities = {}

@main.route('/setup_authority', methods=['POST'])
def setup_authority():
    data = request.json
    authority_name = data['authority_name']
    authority_keys = maabe.authsetup(global_params, authority_name)
    authorities[authority_name] = authority_keys
    return jsonify({'status': 'success', 'authority_name': authority_name})

@main.route('/keygen', methods=['POST'])
def keygen():
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid input data'}), 400

    authority_name = data.get('authority_name')
    attributes = data.get('attributes')  # List of attributes to add
    user_id = data.get('user_id')
    existing_key_hex = data.get('existing_key')  # Optional existing key

    if not authority_name or not attributes or not user_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    print("Authority Name:", authority_name)
    print("Attributes:", attributes)
    print("User ID:", user_id)
    print("Authorities:", authorities)

    if authority_name not in authorities:
        return jsonify({'error': f"Authority '{authority_name}' not found"}), 400

    secret_keys = authorities[authority_name][1]

    # Deserialize the existing key, if provided
    existing_key = {}
    if existing_key_hex:
        try:
            existing_key = bytesToObject(bytes.fromhex(existing_key_hex), group)
        except Exception as e:
            print("Error deserializing existing key:", str(e))
            return jsonify({'error': 'Invalid existing key format'}), 400

    try:
        # Generate keys for the new attributes and merge them
        for attribute in attributes:
            user_key = maabe.keygen(global_params, secret_keys, user_id, attribute.upper())

            # Merge the new key into the existing key
            if 'keys' not in existing_key:
                existing_key['keys'] = {}
            existing_key['keys'][attribute.upper()] = user_key

        if 'GID' not in existing_key:
            existing_key['GID'] = user_id

        # Serialize the updated key
        serialized_key = objectToBytes(existing_key, group).hex()
        return jsonify({'status': 'success', 'user_key': serialized_key})
    except Exception as e:
        print("Keygen Error:", str(e))
        return jsonify({'error': f"Key generation failed: {str(e)}"}), 500

@main.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    if not data or 'policy' not in data:
        return jsonify({'error': 'Missing required parameter: policy'}), 400

    try:
        policy = data['policy']
        message = group.random(GT)  # Replace with group.hash for deterministic data
        public_keys = {auth: authorities[auth][0] for auth in authorities}  # Adjusted for your structure
        ciphertext = maabe.encrypt(global_params, public_keys, message, policy)
        serialized_ciphertext = objectToBytes(ciphertext, group).hex()
        serialized_message = objectToBytes(message, group).hex()
        return jsonify({'ciphertext': serialized_ciphertext, 'message': serialized_message})
    except Exception as e:
        print("Encryption Error:", str(e))
        return jsonify({'error': f"Encryption failed: {str(e)}"}), 500

@main.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    if not data or 'keys' not in data or 'ciphertext' not in data:
        return jsonify({'error': 'Missing required parameters: keys, ciphertext'}), 400

    try:
        serialized_keys = bytes.fromhex(data['keys'])
        serialized_ciphertext = bytes.fromhex(data['ciphertext'])
        user_keys = bytesToObject(serialized_keys, group)
        ciphertext = bytesToObject(serialized_ciphertext, group)
        message = maabe.decrypt(global_params, user_keys, ciphertext)
        return jsonify({'decrypted_message': objectToBytes(message, group).hex()})
    except Exception as e:
        print("Decryption Error:", str(e))
        return jsonify({'error': f"Decryption failed: {str(e)}"}), 500

