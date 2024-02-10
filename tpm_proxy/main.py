from fastapi import FastAPI, Request
import subprocess
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import base64
import requests

app = FastAPI()

origins = ["*", "http://tpmserver", "http://tpmproxy"]

try:
    # Try to init the proxy service
    print("Following handles are in use:")
    handles = subprocess.run(["tpm2_getcap", "handles-persistent"], capture_output=True)
    print(handles.stdout.decode())
    if "0x81010002" and "0x81010003" in handles.stdout.decode():
        print("EK & AK have persistent handles")
        generate_ak = subprocess.run(
            [
                "tpm2_createak",
                "-C",
                "0x81010002",
                "-c",
                "ak.ctx",
                "-G",
                "rsa",
                "-g",
                "sha256",
                "-s",
                "rsassa",
                "-u",
                "ak.pub",
                "-f",
                "pem",
                "-n",
                "ak.name",
            ],
            capture_output=True,
        )
    else:
        print("Need to load EK & AK for message signing")
        generate_ek = subprocess.run(
            ["tpm2_createek", "-c", "0x81010002", "-G", "rsa", "-u", "ek.pub"],
            capture_output=True,
        )
        generate_ak = subprocess.run(
            [
                "tpm2_createak",
                "-C",
                "0x81010002",
                "-c",
                "ak.ctx",
                "-G",
                "rsa",
                "-g",
                "sha256",
                "-s",
                "rsassa",
                "-u",
                "ak.pub",
                "-f",
                "pem",
                "-n",
                "ak.name",
            ],
            capture_output=True,
        )
        print(generate_ak.stdout.decode())
        persist_ak = subprocess.run(
            ["tpm2_evictcontrol", "-c", "ak.ctx", "0x81010003"], capture_output=True
        )
        print(persist_ak.stdout.decode())
        handles = subprocess.run(
            ["tpm2_getcap", "handles-persistent"], capture_output=True
        )
        if "0x81010002" and "0x81010003" in handles.stdout.decode():
            print("EK & AK have persistent handles")
        else:
            print("Something went wrong!")
            exit(1)
    print("Waiting for connections")
except OSError:
    print("Cannot start the proxy service, is the port in use?")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"Proxy Status": "UP"}


@app.get("/pem")
async def get_pem():
    pem_file_gen = subprocess.run(
        ["tpm2_readpublic", "-c", "0x81010003", "-o", "pub_gen/ak.pem", "-f", "pem"]
    )
    with open("pub_gen/ak.pem", "r") as pubkey:
        public = ""
        public = pubkey.read()

    requests.post(url="http://tpmserver:8000/pubkey", data=public.encode())

    return {"public_key": public}


@app.post("/proxy")
async def verify_token(request: Request):
    verify_token = request.headers.get("Authorization")
    verify_address = request.headers.get("Target-URL")
    get_data = await request.body()

    get_headers = {}
    for name, value in request.headers.items():
        get_headers[name] = value

    verify_token = verify_token.split(" ")[1]
    sha256_token = hashlib.sha256(verify_token.encode())
    name_of_file = str(sha256_token.hexdigest())
    token = ""
    existing_token = False
    try:
        with open("tokens/" + name_of_file, "r") as existing:
            token = existing.readlines()
            existing_token = True

    except FileNotFoundError:
        with open("tokens/" + name_of_file, "w") as not_existing:
            not_existing.write(name_of_file)
            print("Created file for the hashed token")
    signature_file = "signatures/" + name_of_file + ".sig"
    token_file = "tokens/" + name_of_file

    if existing_token == False:
        subprocess.run(
            [
                "tpm2_sign",
                "-c",
                "0x81010003",
                "-g",
                "sha256",
                "-o",
                signature_file,
                token_file,
            ],
            capture_output=True,
        )

        pem_file_shorten = subprocess.run(
            [
                "dd",
                f"if={signature_file}",
                f"of=signatures/{name_of_file}.raw",
                "bs=1",
                "skip=6",
                "count=256",
            ]
        )
    b64_signature = ""
    with open(f"signatures/{name_of_file}.raw", "rb") as b64sig:
        b64_signature = b64sig.read()
        b64_signature = base64.b64encode(b64_signature)
    get_headers["SignatureJWT"] = b64_signature

    result = requests.post(url=verify_address, data=get_data, headers=get_headers)

    return {result.text}
