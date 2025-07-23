import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils
from cryptography.hazmat.primitives import serialization, kdf
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import os

# --- Helper functions (Simplified for pseudocode) ---
# Note: RSA is now only used conceptually for certificates/authentication, not direct content encryption.
# The ECDSA keys are the long-term signing keys.

class ECDSA:
    @staticmethod
    def generate_keys():
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )
        public_key = private_key.public_key()
        return public_key, private_key

    @staticmethod
    def sign(message_bytes, private_key):
        # Hash the message before signing
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(message_bytes)
        digest = hasher.finalize()
        return private_key.sign(
            digest, # Sign the hash, not the raw message
            ec.ECDSA(hashes.SHA256()) # Indicate hashing algorithm used for signing
        )

    @staticmethod
    def verify(message_bytes, signature, public_key):
        try:
            # Hash the message before verification, using the same algorithm as signing
            hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher.update(message_bytes)
            digest = hasher.finalize()
            public_key.verify(
                signature,
                digest, # Verify against the hash
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

class AES:
    @staticmethod
    def encrypt(data_bytes, key):
        iv = os.urandom(16) # Initialization Vector for GCM mode
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data_bytes) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag # Return IV, ciphertext, and authentication tag

    @staticmethod
    def decrypt(iv, ciphertext, tag, key):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class ECDH:
    @staticmethod
    def generate_keys():
        private_key = ec.generate_private_key(
            ec.SECP256R1(), # Standard elliptic curve
            default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(private_key_own, public_key_other, info_bytes):
        # Perform the ECDH key exchange to get a shared secret
        shared_secret = private_key_own.exchange(ec.ECDH(), public_key_other)
        # Use HKDF to derive a strong, fixed-length key (32 bytes for AES-256) from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits for AES-256
            salt=None, # For simplicity; in real systems, use a unique, random salt per session
            info=info_bytes, # Contextual information to bind the key to its purpose
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key

# --- 1. Key Generation (Long-term keys for Digital Signatures) ---
# These keys would be securely stored and managed by each entity, potentially within hardware security modules (HSMs).
print("--- 1. Key Generation ---")
HR_sign_pub, HR_sign_priv = ECDSA.generate_keys()
SS_sign_pub, SS_sign_priv = ECDSA.generate_keys()
MH_sign_pub, MH_sign_priv = ECDSA.generate_keys()
print("ECDSA signing keys generated for HR, SS, MH.")

# --- 2. Secure Channel Establishment (First-Time Communication) ---
# This simulates an authenticated TLS/SSL-like handshake for session key derivation.
# In a real scenario, this involves mutual authentication using digital certificates
# signed by a trusted Certificate Authority (CA) to bind public keys to identities.

# 2a. HR <--> SS Channel Establishment
print("\n--- 2a. HR <--> SS Channel Establishment (Authenticated ECDH) ---")
# Ephemeral ECDH keys for this session key derivation
hr_ecdh_ephemeral_priv_ss, hr_ecdh_ephemeral_pub_ss = ECDH.generate_keys()
ss_ecdh_ephemeral_priv, ss_ecdh_ephemeral_pub = ECDH.generate_keys()

# In a real TLS handshake, the ECDH public keys would be signed by the long-term
# signing keys (e.g., from certificates) to authenticate the exchange.
# Contextual info for key derivation (e.g., protocol version, cipher suite)
info_hr_ss = b"HR_SS_Secure_Channel_Key_Derivation"
K_HR_SS = ECDH.derive_shared_key(hr_ecdh_ephemeral_priv_ss, ss_ecdh_ephemeral_pub, info_hr_ss)
print(f"Shared symmetric session key K_HR_SS derived (Length: {len(K_HR_SS)*8} bits).")

# 2b. HR <--> MH Channel Establishment
print("\n--- 2b. HR <--> MH Channel Establishment (Authenticated ECDH) ---")
# Ephemeral ECDH keys for this session key derivation
hr_ecdh_ephemeral_priv_mh, hr_ecdh_ephemeral_pub_mh = ECDH.generate_keys()
mh_ecdh_ephemeral_priv, mh_ecdh_ephemeral_pub = ECDH.generate_keys()

# Similar authentication process as above would occur here.
info_hr_mh = b"HR_MH_Secure_Channel_Key_Derivation"
K_HR_MH = ECDH.derive_shared_key(hr_ecdh_ephemeral_priv_mh, mh_ecdh_ephemeral_pub, info_hr_mh)
print(f"Shared symmetric session key K_HR_MH derived (Length: {len(K_HR_MH)*8} bits).")

# --- 3. Contract Exchange Transaction ---

# Step 3.1: SS → HR (Send Contract)
print("\n--- 3.1: SS → HR (Send Contract) ---")
C = "This is the legally binding property contract text for Mrs. Harvey's land purchase. Dated July 23, 2025.".encode('utf-8')
print(f"Original Contract (SS): {C[:70]}...")

# SS encrypts the contract with K_HR_SS (AES-256 GCM)
iv_ss_hr, cipher_C, tag_ss_hr = AES.encrypt(C, K_HR_SS)
# SS signs the HASH of the contract with their private key (ECDSA)
signature_SS = ECDSA.sign(C, SS_sign_priv)

message_SS_HR = {
    "iv": iv_ss_hr.hex(), # Convert IV to hex for transfer
    "cipher": cipher_C.hex(), # Convert ciphertext to hex
    "tag": tag_ss_hr.hex(),   # Convert tag to hex
    "signature": signature_SS.hex() # Convert signature to hex
}
print("SS sends encrypted contract and signature to HR.")

# HR receives and processes
try:
    # Convert hex back to bytes for decryption/verification
    received_iv_ss_hr = bytes.fromhex(message_SS_HR["iv"])
    received_cipher_C = bytes.fromhex(message_SS_HR["cipher"])
    received_tag_ss_hr = bytes.fromhex(message_SS_HR["tag"])
    received_signature_SS = bytes.fromhex(message_SS_HR["signature"])

    C_decrypted_by_HR = AES.decrypt(received_iv_ss_hr, received_cipher_C, received_tag_ss_hr, K_HR_SS)
    print("HR: Contract decrypted successfully.")

    # Verify SS's signature against the decrypted contract content
    is_signature_valid = ECDSA.verify(C_decrypted_by_HR, received_signature_SS, SS_sign_pub)
    print(f"HR: SS's signature verification: {is_signature_valid}")

    assert is_signature_valid, "SS's signature is invalid!"
    assert C_decrypted_by_HR == C, "Decrypted contract does not match original!"
    print("HR: Contract integrity and authenticity from SS verified.")
except Exception as e:
    print(f"HR: Error processing message from SS: {e}")
    # In a real system, this would trigger an error response or transaction abort.

# Step 3.2: HR → MH (Forward Contract)
print("\n--- 3.2: HR → MH (Forward Contract) ---")
# HR encrypts the contract (C_decrypted_by_HR) with K_HR_MH (AES-256 GCM)
iv_hr_mh, cipher_C_MH, tag_hr_mh = AES.encrypt(C_decrypted_by_HR, K_HR_MH)

# HR optionally signs the forwarded contract to attest it came from them (ECDSA)
signature_HR_forward = ECDSA.sign(C_decrypted_by_HR, HR_sign_priv)

message_HR_MH = {
    "iv": iv_hr_mh.hex(),
    "cipher": cipher_C_MH.hex(),
    "tag": tag_hr_mh.hex(),
    "signature_HR_forward": signature_HR_forward.hex() # HR's signature on the forwarded content
}
print("HR sends encrypted contract and its forwarding signature to MH.")

# MH receives and processes
try:
    received_iv_hr_mh = bytes.fromhex(message_HR_MH["iv"])
    received_cipher_C_MH = bytes.fromhex(message_HR_MH["cipher"])
    received_tag_hr_mh = bytes.fromhex(message_HR_MH["tag"])
    received_signature_HR_forward = bytes.fromhex(message_HR_MH["signature_HR_forward"])

    C_decrypted_by_MH = AES.decrypt(received_iv_hr_mh, received_cipher_C_MH, received_tag_hr_mh, K_HR_MH)
    print("MH: Contract decrypted successfully.")

    # Verify HR's forwarding signature against the decrypted contract
    is_hr_signature_valid = ECDSA.verify(C_decrypted_by_MH, received_signature_HR_forward, HR_sign_pub)
    print(f"MH: HR's forwarding signature verification: {is_hr_signature_valid}")

    assert is_hr_signature_valid, "HR's forwarding signature is invalid!"
    assert C_decrypted_by_MH == C, "Decrypted contract does not match original!" # MH now has the original contract
    print("MH: Contract integrity and authenticity from HR verified.")
except Exception as e:
    print(f"MH: Error processing message from HR: {e}")
    # Handle error

# Step 3.3: MH → HR (Sign Contract and Return)
print("\n--- 3.3: MH → HR (Sign Contract and Return) ---")
# MH signs the contract (C_decrypted_by_MH) with her private key (legally binding ECDSA signature)
signature_MH_final = ECDSA.sign(C_decrypted_by_MH, MH_sign_priv)

# Bundle contract and MH's signature for encryption. Use a clear delimiter for parsing.
signed_contract_bundle_mh = C_decrypted_by_MH + b"###MH_SIGNATURE###" + signature_MH_final

# MH encrypts the bundle with K_HR_MH (AES-256 GCM)
iv_mh_hr, cipher_signed_C_MH, tag_mh_hr = AES.encrypt(signed_contract_bundle_mh, K_HR_MH)

message_MH_HR = {
    "iv": iv_mh_hr.hex(),
    "cipher": cipher_signed_C_MH.hex(),
    "tag": tag_mh_hr.hex(),
}
print("MH sends encrypted signed contract to HR.")

# HR receives and processes
try:
    received_iv_mh_hr = bytes.fromhex(message_MH_HR["iv"])
    received_cipher_signed_C_MH = bytes.fromhex(message_MH_HR["cipher"])
    received_tag_mh_hr = bytes.fromhex(message_MH_HR["tag"])

    decrypted_bundle_by_HR = AES.decrypt(received_iv_mh_hr, received_cipher_signed_C_MH, received_tag_mh_hr, K_HR_MH)
    print("HR: Signed contract bundle decrypted successfully.")

    # HR parses the bundle to extract contract and MH's signature
    parts = decrypted_bundle_by_HR.split(b"###MH_SIGNATURE###")
    C_verified_by_HR = parts[0]
    signature_MH_received = parts[1]

    # HR verifies Mrs. Harvey's signature against the extracted contract
    is_mh_signature_valid = ECDSA.verify(C_verified_by_HR, signature_MH_received, MH_sign_pub)
    print(f"HR: Mrs. Harvey's signature verification: {is_mh_signature_valid}")

    assert is_mh_signature_valid, "Mrs. Harvey's signature is invalid!"
    assert C_verified_by_HR == C, "Contract content from MH does not match original!"
    print("HR: Mrs. Harvey's signature on contract verified.")
except Exception as e:
    print(f"HR: Error processing message from MH: {e}")
    # Handle error

# Step 3.4: HR → SS (Send Signed Contract to Seller's Solicitor)
print("\n--- 3.4: HR → SS (Send Signed Contract to Seller's Solicitor) ---")
# HR bundles the original contract, MH's signature, and optionally HR's attestation signature
final_bundle_hr_ss_content = C_verified_by_HR + b"###MH_FINAL_SIGNATURE###" + signature_MH_received

# HR signs this entire final bundle with its private key for attestation (ECDSA)
signature_HR_final = ECDSA.sign(final_bundle_hr_ss_content, HR_sign_priv)

# HR encrypts the final bundle using K_HR_SS (AES-256 GCM)
iv_hr_ss_final, cipher_final_bundle, tag_hr_ss_final = AES.encrypt(final_bundle_hr_ss_content, K_HR_SS)

message_HR_SS = {
    "iv": iv_hr_ss_final.hex(),
    "cipher": cipher_final_bundle.hex(),
    "tag": tag_hr_ss_final.hex(),
    "signature_HR_final": signature_HR_final.hex() # HR's attestation signature
}
print("HR sends encrypted signed contract and its final attestation signature to SS.")

# SS receives and processes (Final Verification)
try:
    received_iv_hr_ss_final = bytes.fromhex(message_HR_SS["iv"])
    received_cipher_final_bundle = bytes.fromhex(message_HR_SS["cipher"])
    received_tag_hr_ss_final = bytes.fromhex(message_HR_SS["tag"])
    received_signature_HR_final = bytes.fromhex(message_HR_SS["signature_HR_final"])

    decrypted_final_bundle_by_SS = AES.decrypt(received_iv_hr_ss_final, received_cipher_final_bundle, received_tag_hr_ss_final, K_HR_SS)
    print("SS: Final bundle decrypted successfully.")

    # SS first verifies HR's final attestation signature on the entire bundle
    is_hr_final_signature_valid = ECDSA.verify(decrypted_final_bundle_by_SS, received_signature_HR_final, HR_sign_pub)
    print(f"SS: HR's final attestation signature verification: {is_hr_final_signature_valid}")

    assert is_hr_final_signature_valid, "HR's final attestation signature is invalid!"
    print("SS: HR's attestation verified.")

    # SS then parses the bundle to get the original contract and Mrs. Harvey's signature
    parts_final = decrypted_final_bundle_by_SS.split(b"###MH_FINAL_SIGNATURE###")
    C_final_by_SS = parts_final[0]
    signature_MH_final_by_SS = parts_final[1]

    # SS verifies Mrs. Harvey's legally binding signature against the original contract content
    is_mh_final_signature_valid = ECDSA.verify(C_final_by_SS, signature_MH_final_by_SS, MH_sign_pub)
    print(f"SS: Mrs. Harvey's legally binding signature verification: {is_mh_final_signature_valid}")

    assert is_mh_final_signature_valid, "Mrs. Harvey's final legally binding signature is invalid!"
    assert C_final_by_SS == C, "Final contract content does not match original!"
    print("SS: Mrs. Harvey's legally binding signature on contract verified. Transaction complete. ✅")
except Exception as e:
    print(f"SS: Error processing final message from HR: {e}")
    # Handle error, potentially reject transaction and initiate re-negotiation

