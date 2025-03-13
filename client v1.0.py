#!/usr/bin/env python3
import os
import asyncio
import websockets
import logging
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Generate X25519 key pair
def generate_x25519_key():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

# Derive shared AES key
def derive_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    return derived_key

# AES-GCM encryption & decryption functions
def encrypt_message(aes_key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_message(aes_key, encrypted_data):
    if len(encrypted_data) < 28:
        raise ValueError(f"Encrypted data too short: {len(encrypted_data)} bytes")
    iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# WebSocket client
async def connect_to_server():
    uri = input("[+] Enter Server URI (e.g., ws://localhost:4000): ")
    try:
        async with websockets.connect(uri) as websocket:
            logger.info("[+] Connected to Server")

            # Key exchange
            client_private_key, client_public_key = generate_x25519_key()
            logger.debug(f"Generated client public key: {serialize_public_key(client_public_key).hex()}")
            server_public_key_bytes = await websocket.recv()
            logger.debug(f"Received server public key: {server_public_key_bytes.hex()} (length: {len(server_public_key_bytes)})")
            if len(server_public_key_bytes) != 32:
                raise ValueError(f"Invalid server public key length: {len(server_public_key_bytes)}")
            await websocket.send(serialize_public_key(client_public_key))
            logger.debug("Client public key sent to server")
            shared_aes_key = derive_shared_key(client_private_key, server_public_key_bytes)
            logger.info("[+] Shared AES Key Established!")

            # Receive messages task
            async def receive_messages():
                while True:
                    try:
                        encrypted_data = await websocket.recv()
                        logger.debug(f"Received encrypted data: {encrypted_data.hex()}")
                        decrypted_message = decrypt_message(shared_aes_key, encrypted_data).decode('utf-8')
                        logger.info(f"[Server]: {decrypted_message}")
                    except websockets.ConnectionClosed as e:
                        logger.info(f"[+] Server disconnected: {e}")
                        break
                    except Exception as e:
                        logger.error(f"Error in receiving data: {e}")
                        break

            logger.debug("Starting receive_messages task")
            asyncio.create_task(receive_messages())
            logger.debug("receive_messages task started")

            # Send messages
            while True:
                message = await asyncio.to_thread(input, "[You]: ")
                if message.lower() == "quit":
                    break
                encrypted_message = encrypt_message(shared_aes_key, message)
                logger.debug(f"Sending encrypted data: {encrypted_message.hex()}")
                await websocket.send(encrypted_message)

    except websockets.ConnectionClosed as e:
        logger.error(f"Connection closed with error: {e}")
    except Exception as e:
        logger.error(f"Connection error: {e}")
    finally:
        logger.info("[+] Client closed")

if __name__ == "__main__":
    asyncio.run(connect_to_server())
