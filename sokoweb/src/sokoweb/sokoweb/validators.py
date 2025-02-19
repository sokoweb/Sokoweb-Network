# validators.py

from pydantic import ValidationError
from .models import CoreAttributes

class ProductValidator:
  def validate(self, product_in):
      try:
          # Validate core attributes using Pydantic
          core = product_in.core.dict()
          CoreAttributes(**core)
          # Extended attributes can be left flexible or further validation can be added
          return True, None
      except ValidationError as e:
          return False, e.errors()