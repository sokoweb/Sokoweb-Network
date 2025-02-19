# remote_node.py

import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import ed25519

class RemoteNode:
    def __init__(self, ip, port, node_id=None, public_key_bytes=None, tcp_port=None):
        self.ip = ip
        self.port = port
        self.tcp_port = tcp_port or port
        self.node_id = node_id
        self.public_key_bytes = public_key_bytes
        self.public_key = None
        self.is_unresponsive = False
        self.unresponsive_count = 0

        if self.public_key_bytes:
            self._setup_public_key()

    def _setup_public_key(self):
        try:
            if isinstance(self.public_key_bytes, str):
                self.public_key_bytes = bytes.fromhex(self.public_key_bytes)
            self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                self.public_key_bytes
            )
        except Exception as e:
            self.public_key = None

    def __eq__(self, other):
        if isinstance(other, RemoteNode):
            return self.node_id == other.node_id
        return False

    def __hash__(self):
        return hash(self.node_id)