MA-ABE Flask API

This is a simple Flask API that implements a Multi-Authority Attribute-Based Encryption (MA-ABE) scheme.
Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.
Prerequisites

    Docker

    Docker Compose

Installation

    Clone the repo

    git clone https://github.com/ma-abe-flask/ma-abe-flask.git

    Navigate to the project directory

    cd ma-abe-flask

Deployment

To deploy the application, run the following command in the root of the project directory:

docker-compose up

The API will be available at http://localhost:8080.
API Documentation (Swagger)

Once the application is running, you can access the Swagger UI for API documentation and testing at:

http://localhost:8080/api/docs
API Usage

The API provides endpoints for setting up authorities, generating user keys, and encrypting/decrypting messages.
1. Setup an Authority

To use the encryption and decryption features, you first need to set up one or more authorities.

    Endpoint: POST /api/setup_authority

    Request Body:

    {
      "authority_name": "your_authority_name"
    }

    Example using cURL:

    curl -X POST "http://localhost:8080/api/setup_authority" -H "Content-Type: application/json" -d '{"authority_name": "authority1"}'

2. Generate a User Key

Next, generate a key for a user with specific attributes from an authority.

    Endpoint: POST /api/keygen

    Request Body:

    {
      "authority_name": "your_authority_name",
      "attributes": ["attribute1", "attribute2"],
      "user_id": "your_user_id"
    }

    Example using cURL:

    curl -X POST "http://localhost:8080/api/keygen" -H "Content-Type: application/json" -d '{"authority_name": "authority1", "attributes": ["doctor", "researcher"], "user_id": "user1"}'

3. Encrypt a Message

Encrypt a message with a policy that defines which attributes are required for decryption.

    Endpoint: POST /api/encrypt

    Request Body:

    {
      "policy": "your_policy",
      "payload": "your_message"
    }

    The policy should be a boolean expression of attributes, for example (doctor@authority1 AND researcher@authority1).

    Example using cURL:

    curl -X POST "http://localhost:8080/api/encrypt" -H "Content-Type: application/json" -d '{"policy": "(doctor@authority1 AND researcher@authority1)", "payload": "This is a secret message"}'

4. Decrypt a Message

Decrypt a previously encrypted message using a user's key.

    Endpoint: POST /api/decrypt

    Request Body:

    {
      "user_id": "your_user_id",
      "payload": "the_encrypted_payload"
    }

    Example using cURL:

    curl -X POST "http://localhost:8080/api/decrypt" -H "Content-Type: application/json" -d '{"user_id": "user1", "payload": "the_long_encrypted_string_from_the_encrypt_endpoint"}'

