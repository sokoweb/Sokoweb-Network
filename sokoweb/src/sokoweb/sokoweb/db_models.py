# db_models.py

from sqlalchemy import Column, String, Float, Boolean, LargeBinary, JSON
from sqlalchemy.dialects.postgresql import UUID
import uuid

from .database import Base


class User(Base):
  __tablename__ = 'users'

  id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
  username = Column(String, unique=True, index=True, nullable=False)
  email = Column(String, nullable=True)
  full_name = Column(String, nullable=True)
  hashed_password = Column(String, nullable=False)
  disabled = Column(Boolean, default=False)
  scopes = Column(String, nullable=True)  # Comma-separated string of scopes
  credits = Column(Float, default=0.0)
  phone_number = Column(String, nullable=True)  # Added phone_number field

  # Relationships can be added if needed, e.g., products


class Product(Base):
    __tablename__ = "products"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_id = Column(String, unique=True, index=True, nullable=False)
    # Core attributes
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    category = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    image_refs = Column(JSON, nullable=True)  # Store as JSON
    seller_location = Column(JSON, nullable=True)  # Store as JSON
    shop_name = Column(String, nullable=True)
    seller_phone_encrypted = Column(LargeBinary, nullable=True)
    # Extended attributes
    extended_attributes = Column(JSON, nullable=True)


  # Relationships can be added if needed

class NodeCredit(Base):
    __tablename__ = 'node_credits'

    node_id = Column(String, primary_key=True)
    credits = Column(Float, default=0.0)