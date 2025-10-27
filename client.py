import oqs
import socket
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
KEM_ALGORITHM = "Kyber768"        # ML-KEM
SIG_ALGORITHM = "Dilithium3"     # ML-DSA
HOST = '127.0.0.1'               # The server's IP
PORT = 65432                     # The server's port

# --- PQC Sizing (for socket.recv) ---
# Must match the server's algorithms
# Kyber768
KEM_PUBLIC_KEY_SIZE = 1184
KEM_CIPHERTEXT_SIZE = 1088
# Dilithium3
SIG_PUBLIC_KEY_SIZE = 1952
SIG_SIGNATURE_SIZE = 3293
# ------------------------------------

print("🚀 Starting PQC Client (Bob)...")

# 1. Initialize PQC algorithm handlers
kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
sig = oqs.Signature(SIG_ALGORITHM)

# 2. Connect to the server
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        # 3. Receive the 3 items from the server
        print("Receiving authentication data from server...")
        
        # We must receive in the exact order the server sent
        server_sig_public_key = s.recv(SIG_PUBLIC_KEY_SIZE)
        server_kem_public_key = s.recv(KEM_PUBLIC_KEY_SIZE)
        signature = s.recv(SIG_SIGNATURE_SIZE)

        # Basic check to ensure we got all the data
        if not (server_sig_public_key and server_kem_public_key and signature):
            print("❌ Connection closed by server prematurely. Aborting.")
            sys.exit(1)

        print("Received all data. Verifying signature...")

        # 4. --- CRITICAL STEP: VERIFY SIGNATURE ---
        #    Use the server's public signature key to check if the
        #    signature is valid for the KEM public key.
        is_valid = sig.verify(server_sig_public_key, server_kem_public_key, signature)

        if not is_valid:
            print("="*40)
            print("❌❌❌ SIGNATURE VERIFICATION FAILED! ❌❌❌")
            print("This is a Man-in-the-Middle (MITM) attack!")
            print("The server is NOT who they claim to be. Aborting.")
            print("="*40)
            sys.exit(1) # Exit the script immediately
        
        print("✅ Signature is valid! Server is authentic.")

        # 5. --- PROCEED WITH KEM ---
        #    Now that we TRUST the KEM public key, we can use it.
        print("Encapsulating secret using trusted KEM public key...")
        ciphertext, shared_secret = kem.encapsulate_secret(server_kem_public_key)
        
        aes_key = shared_secret # Use this as our AES key

        # 6. Send the 'ciphertext' to the server
        print("Sending ciphertext to server...")
        s.sendall(ciphertext)

        # 7. Encrypt and send our secret message
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12) # Must be random for each encryption
        message = b"This message was fully authenticated and encrypted!"

        encrypted_data = aesgcm.encrypt(nonce, message, None)

        print("Sending encrypted message...")
        s.sendall(nonce)
        s.sendall(encrypted_data)
        
        print("\n🎉 FULL SUCCESS: Message sent securely.")

except ConnectionRefusedError:
    print(f"❌ Connection Error: Could not connect to {HOST}:{PORT}.")
    print("   Is the server.py script running in another terminal?")
except Exception as e:
    print(f"An error occurred: {e}")

print("Client shutting down.")
