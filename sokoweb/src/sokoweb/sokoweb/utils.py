import hashlib

def generate_node_id(public_key_bytes):
  # Use SHA-1 hash of the public key as the node ID
  node_id = hashlib.sha1(public_key_bytes).hexdigest()
  return node_id

def xor_distance(id1, id2):
  return int(id1, 16) ^ int(id2, 16)
