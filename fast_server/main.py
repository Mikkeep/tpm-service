import hashlib
from fastapi import FastAPI, Header, Body, Request
from jose import jwt
import OpenSSL
import subprocess
import base64
from fastapi.middleware.cors import CORSMiddleware
import random
import string

# Pycryptodome for signature verification
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# UTIL For Signature checking
def ver_sig(pub_path, sig, data):

    with open(pub_path, "rb") as pub_key:
        pubkey = RSA.import_key(pub_key.read())

    hash = SHA256.new(data.encode())

    try:
        pkcs1_15.new(pubkey).verify(hash, sig)
        return True
    except Exception as e:
        print(e)
    return False


app = FastAPI()

SEC_KEY = "8499a1eb1487748e39e985413bd33d7349f76457fb77a696d601f430ee86ca1f"
ALGO = "HS256"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/generate_token")
async def gen_token():
    # datadict = {"Bob": "Alice"}
    random_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
    print(random_data)
    datadict = {"Bob": random_data}
    enc_jwt = jwt.encode(datadict, SEC_KEY, ALGO)
    print(enc_jwt)
    return enc_jwt


@app.post("/pubkey/{num}")
async def make_key(request: Request, num: str):
    content = await request.body()
    print(content.decode())
    with open(f"pubkeys/ak_{str(num)}.pem", "w") as pubkey:
        pubkey.write(content.decode())
    return {f"Wrote public key to a file": "ak_{str(num)}.pem"}


@app.post("/verify/{num}")
async def verify_token(request: Request, num: str):
    verify_token = request.headers.get("Authorization")
    verify_token = verify_token.split(" ")[1]
    verify_token_orig = verify_token
    # For some reason the resulting string needs to be shortened to be considered valid
    verify_token = repr(verify_token)[2:-2]
    try:
        check_sig = jwt.decode(verify_token, SEC_KEY, ALGO)
    except Exception as e:
        print("Following exception happened: " + str(e))
    verify_sig_res = {}

    sha256_token = hashlib.sha256(verify_token_orig.encode()).hexdigest()
    verify_signature = request.headers.get("SignatureJWT")
    verify_signature = base64.b64decode(verify_signature)

    pth = f"./pubkeys/ak_{str(num)}.pem"
    res = ver_sig(pth, verify_signature, sha256_token)
    verify_sig_res = {}
    if res:
        verify_sig_res = {
            "Result": True,
            "Stdout": "Signature verified successfully",
        }
        verify_sig_res["Secret"] = (
            "This message is only given for those who have been granted entry by the mighty TPM!",
        )
    else:
        verify_sig_res = {"Result": False, "Stdout": "Signature check failed"}
    return {"HMM": verify_sig_res}
