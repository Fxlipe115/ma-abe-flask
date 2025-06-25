## MA-ABE Flask API

This is a simple Flask API that implements a Multi-Authority Attribute-Based Encryption (MA-ABE) scheme.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

* Docker
* Docker Compose

### Installation

1.  Clone the repo
    ```sh
    git clone [https://github.com/ma-abe-flask/ma-abe-flask.git](https://github.com/ma-abe-flask/ma-abe-flask.git)
    ```
2.  Navigate to the project directory
    ```sh
    cd ma-abe-flask
    ```

### Deployment

To deploy the application, run the following command in the root of the project directory:

```sh
docker-compose -f docker-compose.yml up --build
```

The API will be available at http://localhost:8080.

### API Documentation (Swagger)

Once the application is running, you can access the Swagger UI for API documentation and testing at:

http://localhost:8080/api/docs

## API Usage

The API provides endpoints for setting up authorities, generating user keys, and encrypting/decrypting messages.
1. Setup an Authority

    To use the encryption and decryption features, you first  need to set up one or more authorities.

    * Endpoint: POST /api/setup_authority

    * Request Body:
      ```json
      {
        "authority_name": "your_authority_name"
      }
      ```

    * Example using cURL:
      ```sh
      curl -X POST "http://localhost:8080/api/setup_authority" -H "Content-Type: application/json" -d '{"authority_name": "AUTHORITY1"}'
      ```

2. Generate a User Key

    Next, generate a key for a user with specific attributes from an authority.

    * Endpoint: POST /api/keygen

    * Request Body:
      ```json
      {
        "authority_name": "your_authority_name",
        "attributes": ["attribute1", "attribute2"],
        "user_id": "your_user_id"
      }
      ```

    * Example using cURL:
      ```sh
      curl -X POST "http://localhost:8080/api/keygen" -H "Content-Type: application/json" -d '{"authority_name": "AUTHORITY1", "attributes": ["DOCTOR@AUTHORITY1", "RESEARCHER@AUTHORITY1"], "user_id": "user1"}'
      ```

3. Encrypt a Message

    Encrypt a message with a policy that defines which attributes are required for decryption.

    * Endpoint: POST /api/encrypt

    * Request Body:
      ```json
      {
        "policy": "your_policy",
        "payload": "your_message"
      }
      ```

      > The policy should be a boolean expression of attributes, for example (DOCTOR@AUTHORITY1 AND RESEARCHER@AUTHORITY1).

    * Example using cURL:
      ```sh
      curl -X POST "http://localhost:8080/api/encrypt" -H "Content-Type: application/json" -d '{"policy": "(DOCTOR@AUTHORITY1 AND RESEARCHER@AUTHORITY1)", "payload": "This is a secret message"}'
      ```

4. Decrypt a Message

    Decrypt a previously encrypted message using a user's key.

    * Endpoint: POST /api/decrypt

    * Request Body:
      ```json
      {
        "user_id": "your_user_id",
        "payload": "the_encrypted_payload"
      }
      ```

    * Example using cURL:
      ```sh
      curl -X POST "http://localhost:8080/api/decrypt" -H "Content-Type: application/json" -d '{"user_id": "user1", "payload": "the_long_encrypted_string_from_the_encrypt_endpoint"}'
      ```

5. Encrypt a File

    Encrypt a file with a policy that defines which attributes are required for decryption.

    * Endpoint: POST /api/encrypt_file

    * Request: This endpoint accepts multipart/form-data.
      * policy: The encryption policy (form field).
      * payload: The file to encrypt (file upload).
    * Response: The encrypted file will be returned as a download. The encryption key is returned in the X-Encryption-Key header.
    
    * Example using cURL:
      ```sh
      curl -X POST "http://localhost:8080/api/encrypt_file" -H "Content-Type: multipart/form-data" -F "policy=(DOCTOR@AUTHORITY1 AND RESEARCHER@AUTHORITY1)" -F "payload=@/path/to/your/file.txt" -o encrypted_file -D headers.txt
      ```

6. Decrypt a File

    Decrypt a previously encrypted file using a user's key.

    * Endpoint: POST /api/decrypt_file
    
    * Request: This endpoint accepts multipart/form-data.
      * user_id: The user ID (form field).
      * encrypted_key_hex: The ABE encrypted key in hex format from the X-Encryption-Key header of the encrypt_file response (form field).
      * ciphertext_file: The encrypted file (file upload).
    
    * Response: The decrypted file will be returned as a download.
    
    * Example using cURL:
      ```sh
      curl -X POST "http://localhost:8080/api/decrypt_file" -H "Content-Type: multipart/form-data" -F "user_id=user1" -F "encrypted_key_hex=<your_encrypted_key>" -F "ciphertext_file=@/path/to/your/encrypted_file" -o decrypted_file.txt
      ```





## Performance Testing with Locust

This project uses Locust for performance testing. A shell script, `test_combinations.sh`, is provided to automate running Locust with different configurations.

### Running the Tests

To run the performance tests, execute the following command:

```sh
./test_combinations.sh
```


This script will:

  1. Create a timestamped directory under test_results/ to store the test results.

  1. Iterate through predefined combinations of workers, threads, users, payload sizes, and policies.

  1. For each combination, it will start the Flask application with the specified number of workers and threads.

  1. Run the Locust test with the specified number of users.

  1. Save the test results in CSV format in the results directory.

### Modifying Test Parameters

You can modify the test parameters by editing the test-combinations.sh script. The script is divided into "Phases" of testing, where each phase focuses on optimizing a different set of parameters.

To change the parameters for a phase, uncomment the corresponding section in the script and modify the lists:

  * `WORKERS_LIST`: A list of worker counts to test.

  * `THREADS_LIST`: A list of thread counts to test.

  * `USERS_LIST`: A list of user loads to test.

  * `PAYLOAD_SIZE_LIST`: A list of payload sizes to test (in bytes).

  * `NUMBER_OF_POLICIES_LIST`: A list of the number of policies to test.

For example, to test with 10, 20, and 30 workers, you would modify the WORKERS_LIST as follows:

```sh
WORKERS_LIST=(10 20 30)
```

The script will then run the tests for all combinations of the parameters you have defined in the active phase.