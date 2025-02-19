# crypto.py
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import os
import logging

logger = logging.getLogger(__name__)

def generate_key_pair():
  private_key = ed25519.Ed25519PrivateKey.generate()
  public_key = private_key.public_key()
  return private_key, public_key

def sign_message(private_key, message_bytes):
    """
    Sign the message bytes using the provided private key.

    :param private_key: The private key object for signing.
    :param message_bytes: The message bytes to sign.
    :return: Signature bytes.
    """
    signature = private_key.sign(message_bytes)
    return signature  # Return bytes



def verify_signature(public_key_bytes, message_bytes, signature_bytes):
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature_bytes, message_bytes)
        return True
    except InvalidSignature:
        return False



def serialize_public_key(public_key):
  return public_key.public_bytes(
      encoding=serialization.Encoding.Raw,
      format=serialization.PublicFormat.Raw
  )

def serialize_private_key(private_key):
  return private_key.private_bytes(
      encoding=serialization.Encoding.Raw,
      format=serialization.PrivateFormat.Raw,
      encryption_algorithm=serialization.NoEncryption()
  )

# Symmetric encryption functions

def derive_key(password: bytes, salt: bytes):
  """
  Derive a symmetric key from a password and salt using PBKDF2.

  :param password: The password bytes.
  :param salt: The salt bytes.
  :return: Derived key bytes.
  """
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,  # AES-256 key length
      salt=salt,
      iterations=100000,
      backend=default_backend()
  )
  key = kdf.derive(password)
  return key

def encrypt_data(key: bytes, data: bytes):
  """
  Encrypt data using AES CBC mode.

  :param key: Symmetric key bytes.
  :param data: Data bytes to encrypt.
  :return: Tuple of (IV, ciphertext).
  """
  iv = os.urandom(16)
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  encryptor = cipher.encryptor()
  # Pad data to block size
  padder = padding.PKCS7(128).padder()
  padded_data = padder.update(data) + padder.finalize()
  ciphertext = encryptor.update(padded_data) + encryptor.finalize()
  return iv + ciphertext  # Prepend IV for use in decryption

def decrypt_data(key: bytes, iv_ciphertext: bytes):
  """
  Decrypt data using AES CBC mode.

  :param key: Symmetric key bytes.
  :param iv_ciphertext: Concatenated IV and ciphertext.
  :return: Decrypted data bytes.
  """
  iv = iv_ciphertext[:16]
  ciphertext = iv_ciphertext[16:]
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  decryptor = cipher.decryptor()
  decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
  # Remove padding
  unpadder = padding.PKCS7(128).unpadder()
  data = unpadder.update(decrypted_padded) + unpadder.finalize()
  return data

def encrypt_phone_number(phone_number: str, password: str) -> bytes:
    """
    Encrypts the phone number using the provided password.

    :param phone_number: The phone number string to encrypt.
    :param password: The password string to derive the key.
    :return: The encrypted data as bytes (salt + iv + ciphertext).
    """
    # Convert strings to bytes
    phone_data = phone_number.encode("utf-8")
    password_bytes = password.encode("utf-8")

    # Generate a random salt
    salt = os.urandom(16)  # 16 bytes salt

    # Derive key from password and salt
    key = derive_key(password_bytes, salt)

    # Encrypt data
    iv_ciphertext = encrypt_data(key, phone_data)

    # Return the concatenation of salt + iv + ciphertext
    return salt + iv_ciphertext

def decrypt_phone_number(encrypted_data: bytes, password: str) -> str:
    """
    Decrypts the encrypted phone number using the provided password.

    :param encrypted_data: The encrypted data bytes (salt + iv + ciphertext).
    :param password: The password string to derive the key.
    :return: The decrypted phone number string.
    """
    # Convert password to bytes
    password_bytes = password.encode("utf-8")

    # Extract the salt
    salt = encrypted_data[:16]  # First 16 bytes
    iv_ciphertext = encrypted_data[16:]

    # Derive key from password and salt
    key = derive_key(password_bytes, salt)

    # Decrypt data
    decrypted_data = decrypt_data(key, iv_ciphertext)

    # Convert bytes to string
    phone_number = decrypted_data.decode("utf-8")
    return phone_number
