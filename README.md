Post-Quantum Authenticated Key Exchange Demo
This project is a functional, end-to-end demonstration of a quantum-safe authenticated key exchange (AKE) in Python.

It shows how a client and server can securely establish a shared secret for symmetric encryption (AES) in a way that is resistant to attacks from both classical and quantum computers. This implementation specifically prevents Man-in-the-Middle (MITM) attacks by using post-quantum digital signatures for authentication.

Features
Key Encapsulation: Uses ML-KEM (CRYSTALS-Kyber), a NIST-standardized PQC algorithm, to securely establish a shared secret.

Authentication: Uses ML-DSA (CRYSTALS-Dilithium), a NIST-standardized PQC digital signature algorithm, to prove the server's identity and prevent MITM attacks.

Hybrid Encryption: Uses the established PQC shared secret as a 32-byte key for the fast, industry-standard AES-256-GCM symmetric cipher.

Implementation: A clear, two-part client/server model using standard Python libraries (oqs, cryptography, socket).

How It Works
This project demonstrates the core "handshake" that will power future secure communication protocols (like TLS 1.4).

The server.py starts and generates two sets of PQC key pairs:

A long-term ML-DSA (Dilithium) signing pair. The public key would be distributed to clients in a real system (like a certificate).

A session-based ML-KEM (Kyber) key pair for this specific connection.

The server signs its own kem_public_key using its sig_private_key. This signature acts as a certificate of ownership.

The client.py connects to the server.

The server sends three items to the client:

Its sig_public_key (the verifier)

Its kem_public_key (the "lockbox")

The signature (the proof of ownership)

The client performs the critical verification step:

It uses the sig_public_key to check if the signature is valid for the kem_public_key.

If verification fails, the client immediately aborts. This detects a Man-in-the-Middle attack.

If the signature is valid, the client now trusts the kem_public_key. It uses it to encapsulate a new shared_secret, which creates a ciphertext.

The client sends this ciphertext to the server.

The server uses its kem_private_key to decapsulate the ciphertext and retrieve the exact same shared_secret.

Both client and server now possess a secure, authenticated, 32-byte shared secret. They use this as the key for AES-256-GCM to exchange an encrypted message.

Prerequisites
Python 3.7+

pip (Python package installer)

Installation
Clone this repository or download the server.py and client.py files into a new directory.

Install the required Python libraries using pip:

Bash

pip install oqs cryptography
Usage
You must use two separate terminal windows to run this project: one for the server and one for the client.

Terminal 1: Start the Server
First, run the server.py script. It will start and wait for a client to connect.

Bash

python server.py
Expected Output:

Starting PQC Server (Alice)...
KEM Algorithm: Kyber768
Signature Algorithm: Dilithium3
Generated KEM and Signature key pairs.
Signed the KEM public key.
Server listening on 127.0.0.1:65432
Terminal 2: Run the Client
In your second terminal, run the client.py script.

Bash

python client.py
The client will automatically connect to the server, perform the full authenticated handshake, send its encrypted message, and then shut down.

Expected Output:

Starting PQC Client (Bob)...
Connected to server at 127.0.0.1:65432
Receiving authentication data from server...
Received all data. Verifying signature...
Signature is valid! Server is authentic.
Encapsulating secret using trusted KEM public key...
Sending ciphertext to server...
Sending encrypted message...

FULL SUCCESS: Message sent securely.
Client shutting down.
Check Server Terminal
If you look back at Terminal 1, you will see the server's output complete, showing the successfully decrypted message from the client.

Expected Output (Continued):

...
Client (Bob) connected from ('127.0.0.1', 51234)
Sending public keys and signature to client...
Received ciphertext from client.
Successfully decapsulated shared secret!
Received encrypted message.

==============================
🎉 FULL SUCCESS! Decrypted Message:
   This message was fully authenticated and encrypted!
==============================

Server shutting down.
⚠️ Disclaimer
This project is an educational demonstration of post-quantum cryptographic concepts. It is not intended for production use without significant hardening, extensive error handling, and integration into a proper Public Key Infrastructure (PKI) and protocol (like TLS).
