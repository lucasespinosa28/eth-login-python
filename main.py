from urllib import response
import uvicorn
import siwe
import os
from secrets import token_hex

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from siwe import SiweMessage

app = FastAPI()

# Note: In a production environment, the secret key should be a long, random
# string and stored securely, for example, as an environment variable.
# For demonstration purposes, a new key is generated on each startup.
# You will need to install `itsdangerous` for SessionMiddleware: `pip install itsdangerous`
SECRET_KEY = os.urandom(24).hex()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SiweVerification(BaseModel):
    message: str
    signature: str


@app.get("/nonce")
async def get_nonce(request: Request):
    """
    Generates a unique, random nonce for the user session.
    This nonce is used to prevent replay attacks.
    """
    request.session["nonce"] = token_hex(16)
    return Response(content=request.session["nonce"], media_type="text/plain")


@app.post("/verify")
async def verify_siwe_message(
    verification: SiweVerification, request: Request, response: Response
):
    """
    Verifies the signed SIWE message from the user.
    If verification is successful, the user's session is authenticated.
    """
    try:
        # Ensure there is a nonce in the session
        nonce = request.session.get("nonce")
        if not nonce:
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return {"ok": False, "message": "Nonce not found in session."}

        siwe_message = SiweMessage.from_message(verification.message)

        # Verify the message signature
        siwe_message.verify(verification.signature, nonce=nonce)

        # Store siwe message in session and consume nonce
        request.session["siwe"] = siwe_message.model_dump_json()
        request.session.pop("nonce")
        return {"ok": True}
    except siwe.ValidationError:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return {"ok": False, "message": "Signature verification failed."}
    except Exception as e:
        # Catch any other exceptions
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"ok": False, "message": str(e)}


@app.get("/me")
async def get_current_user(request: Request):
    """
    Retrieves the authenticated user's information from the session.
    """
    if not request.session.get("siwe"):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"address": None}
    siwe_message = SiweMessage.model_validate_json(request.session["siwe"])
    return {"address": siwe_message.address}


@app.get("/logout")
async def logout(request: Request):
    """
    Logs out the user by clearing the session.
    """
    request.session.clear()
    return {"ok": True}


# To run this application:
# 1. Install necessary packages: pip install "fastapi[all]" siwe itsdangerous
# 2. Run the server: uvicorn main:app --reload
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
