# filepath: /home/lucas/web3/python/login/my-siwe-backend/app/api/routes/auth.py
# Authentication-related endpoints
from fastapi import APIRouter, Depends, Response, HTTPException, status
from siwe import SiweMessage, ValidationError, ExpiredMessage, InvalidSignature, NonceMismatch, generate_nonce
from app.schemas.auth import SiweMessageIn
from app.services.security import create_access_token, get_current_user
import json
import time

router = APIRouter()

# In a real application, you would store nonces in a cache like Redis
# with a short TTL to prevent reuse. For this example, we'll use a
# simple in-memory dictionary.
# In a production system, this simple in-memory NONCE_STORE should be replaced with a more robust solution like Redis or Memcached. This allows the store to be shared across multiple server instances and provides features like automatic key expiration (Time-To-Live, or TTL), which is ideal for managing nonces.
NONCE_STORE = {}

@router.get("/nonce")
def get_nonce():
    nonce = generate_nonce()
    # Store the nonce with a timestamp
    NONCE_STORE[nonce] = time.time()
    return {"nonce": nonce}

@router.post("/verify")
def verify_signature(payload: SiweMessageIn, response: Response):
    message_str = json.dumps(payload.message)
    
    # Check if nonce is valid and hasn't been used
    nonce = payload.message.get("nonce")
    if not nonce or nonce not in NONCE_STORE:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid or expired nonce.",
        )
    
    # Consume the nonce
    del NONCE_STORE[nonce]

    try:
        siwe_message = SiweMessage(message=message_str)
        siwe_message.verify(payload.signature, nonce=nonce)
        
        # If verification is successful, create a JWT
        access_token = create_access_token(
            data={"sub": siwe_message.address}
        )
        
        return {"accessToken": access_token, "tokenType": "bearer"}

    except (ValidationError, ExpiredMessage, InvalidSignature, NonceMismatch) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"SIWE verification failed: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}",
        )

@router.get("/me")
def read_users_me(current_user_address: str = Depends(get_current_user)):
    # By the time this function executes, the token has been validated.
    # The user's address is available in `current_user_address`.
    return {"address": current_user_address}

@router.post("/logout")
def logout(current_user_address: str = Depends(get_current_user)):
    # In a truly stateless JWT system, logout is handled client-side
    # by simply deleting the token. If you need server-side revocation,
    # you would need to implement a token blocklist (e.g., in Redis).
    return {"message": "Logged out successfully"}