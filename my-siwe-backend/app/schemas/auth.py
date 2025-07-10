# Pydantic schemas for auth requests/responses
from pydantic import BaseModel, Json
from typing import Dict, Any

class SiweMessageIn(BaseModel):
    message: Dict[str, Any]
    signature: str