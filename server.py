import oqs
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
KEM_ALGORITHM = "Kyber768"        # ML-KEM
SIG_ALGORITHM = "Dilithium3"     # ML-DSA
HOST = '127.0.0.1'               # Localhost
PORT = 65432                     # Port to listen on

# --- PQC Sizing (for socket.recv) ---
# These are fixed sizes for the chosen algorithms
# Client needs to know these to receive the right amount of data.
# Kyber768
KEM_PUBLIC_KEY_SIZE = 1184
KEM_CIPHERTEXT_SIZE = 1088
# Dilithium3
SIG_PUBLIC_KEY_SIZE = 1952
SIG_SIGNATURE_SIZE = 3293
# ------------------------------------

print("🚀 Starting PQC Server (Alice)...")
print(f"KEM Algorithm: {KEM_ALGORITHM}")
print(f"Signature Algorithm: {SIG_ALGORITHM}")

# 1. Generate KEM key pair (for this session)
kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
server_kem_public_key = kem.generate_keypair()
server_kem_private_key = kem.export_secret_key()

# 2. Generate long-term Signature key pair (to prove identity)
sig = oqs.Signature(SIG_ALGORITHM)
server_sig_public_key = sig.generate_keypair()
server_sig_private_key = sig.export_secret_key()
print("Generated KEM and Signature key pairs.")

# 3. Sign the KEM public key with the private signing key
# This proves the server "owns" the KEM key it's sending.
signature = sig.sign(server_sig_private_key, server_kem_public_key)
print("Signed the KEM public key.")

# 4. Set up the server socket and wait for a connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}")
    
    conn, addr = s.accept()
    with conn:
        print(f"Client (Bob) connected from {addr}")

        # 5. Send all three items to the client
        #    a. The public signature key (so client can verify)
        #    b. The public KEM key (that we're proving is ours)
        #    c. The signature (the proof)
        print("Sending public keys and signature to client...")
        conn.sendall(server_sig_public_key)
        conn.sendall(server_kem_public_key)
        conn.sendall(signature)

        # 6. Receive the ciphertext (encapsulated secret) from the client
        ciphertext = conn.recv(KEM_CIPHERTEXT_SIZE)
        if not ciphertext:
            print("Client disconnected before sending ciphertext.")
            exit()
            
        print("Received ciphertext from client.")

        # 7. Decapsulate the ciphertext to get the shared secret
        shared_secret = kem.decapsulate_secret(server_kem_private_key, ciphertext)
        aes_key = shared_secret  # Kyber768's 32-byte secret is perfect for AES-256
        
        print("✅ Successfully decapsulated shared secret!")

        # 8. Wait to receive an encrypted message
        nonce = conn.recv(12) # 12-byte AES-GCM nonce
        if not nonce:
            print("Client disconnected before sending nonce.")
            exit()

        encrypted_data = conn.recv(1024) # Encrypted message payload
        if not encrypted_data:
            print("Client disconnected before sending encrypted data.")
            exit()
            
        print("Received encrypted message.")

        # 9. Decrypt the message using the shared secret
        try:
            aesgcm = AESGCM(aes_key)
            decrypted_message = aesgcm.decrypt(nonce, encrypted_data, None)
            
            print("\n" + "="*30)
            print("🎉 FULL SUCCESS! Decrypted Message:")
            print(f"   {decrypted_message.decode('utf-8')}")
            print("="*30 + "\n")

        except Exception as e:
            print(f"❌ DECRYPTION FAILED: {e}")
            
print("Server shutting down.")
