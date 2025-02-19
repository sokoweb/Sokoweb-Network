# storage_messages.py

import json
import logging

logger = logging.getLogger(__name__)

class StorageMessage:
    def __init__(self, message_type, sender_id, data, signature=None, public_key=None):
        self.message_type = message_type
        self.sender_id = sender_id
        self.data = data
        self.signature = signature
        self.public_key = public_key

    def to_json_unsigned(self):
        d = {
            "message_type": self.message_type,
            "sender_id": self.sender_id,
            "data": self.data,
        }
        json_str = json.dumps(d, sort_keys=True)
        logger.debug(f"Serialized unsigned storage message to JSON: {json_str}")
        return json_str

    def to_json(self):
        d = {
            "message_type": self.message_type,
            "sender_id": self.sender_id,
            "data": self.data,
            "signature": self.signature,
            "public_key": self.public_key,
        }
        json_str = json.dumps(d, sort_keys=True)
        logger.debug(f"Serialized storage message to JSON: {json_str}")
        return json_str

    @staticmethod
    def from_json(json_str):
        logger.debug(f"Deserializing storage message from JSON: {json_str}")
        obj = json.loads(json_str)
        return StorageMessage(
            message_type=obj["message_type"],
            sender_id=obj["sender_id"],
            data=obj["data"],
            signature=obj.get("signature"),
            public_key=obj.get("public_key"),
        )