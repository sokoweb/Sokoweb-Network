# product.py
import json
import logging
from .crypto import encrypt_phone_number, decrypt_phone_number
from typing import List, Dict, Any
from .models import ImageManifest

logger = logging.getLogger(__name__)

class Product:
    def __init__(
        self,
        product_id,
        core: Dict[str, Any],
        extended: Dict[str, Any] = None,
        image_refs: List[ImageManifest] = None,
        seller_phone_encrypted: bytes = None,
    ):
        self.product_id = product_id
        self.core = core
        self.extended = extended or {}
        self.image_refs = image_refs or []
        self.seller_phone_encrypted = seller_phone_encrypted


    # Add property getters for core attributes
    @property
    def category(self):
        return self.core.get('category')

    @property
    def name(self):
        return self.core.get('name')

    @property
    def description(self):
        return self.core.get('description')

    @property
    def price(self):
        return self.core.get('price')

    @property
    def seller_location(self):
        return self.core.get('seller_location')

    @property
    def shop_name(self):
        return self.core.get('shop_name')

    @property
    def seller_phone(self):
        return self.core.get('seller_phone')

    def encrypt_seller_phone(self, encryption_password):
        seller_phone = self.core.get('seller_phone')
        if seller_phone:
            self.seller_phone_encrypted = encrypt_phone_number(seller_phone, encryption_password)
            self.core['seller_phone'] = None

    def decrypt_seller_phone(self, encryption_password):
        if self.seller_phone_encrypted:
            self.core['seller_phone'] = decrypt_phone_number(
                self.seller_phone_encrypted, encryption_password
            )

    def to_dict(self):
        return {
            "product_id": self.product_id,
            "core": self.core,
            "extended": self.extended,
            "image_refs": [image_ref.dict() for image_ref in self.image_refs],
            "seller_phone_encrypted": self.seller_phone_encrypted.hex()
            if self.seller_phone_encrypted
            else None,
        }


    @staticmethod
    def from_dict(data):
        seller_phone_encrypted_hex = data.get("seller_phone_encrypted")
        seller_phone_encrypted = (
            bytes.fromhex(seller_phone_encrypted_hex)
            if seller_phone_encrypted_hex
            else None
        )

        # Deserialize image_refs
        image_refs_data = data.get("image_refs", [])
        image_refs = [ImageManifest(**ref_data) for ref_data in image_refs_data]

        return Product(
            product_id=data["product_id"],
            core=data["core"],
            extended=data.get("extended"),
            image_refs=image_refs,
            seller_phone_encrypted=seller_phone_encrypted,
        )


    def to_json(self):
        json_str = json.dumps(self.to_dict())
        logger.debug(f"Serialized product {self.product_id} to JSON.")
        return json_str


    @staticmethod
    def from_json(json_str):
        data = json.loads(json_str)
        product = Product.from_dict(data)
        logger.debug(f"Deserialized product {product.product_id} from JSON.")
        return product
