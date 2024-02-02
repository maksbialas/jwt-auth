from fastapi import FastAPI, responses
import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, HTTPException
from fastapi import Request

app = FastAPI()

private_key_path = "./private_key.pem"
public_key_path = "./public_key.pem"

with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)
with open(public_key_path, "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())


def get_current_user(request: Request):
    try:
        jwt_cookie = request.cookies.get("jwt")
        if jwt_cookie is None:
            raise HTTPException(status_code=401, detail="Missing token")

        decoded_jwt = jwt.decode(jwt_cookie, public_key, algorithms=["RS256"])  # type: ignore
        return decoded_jwt
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token")


def has_group(group: str):
    def _has_group(user: dict = Depends(get_current_user)):
        if "groups" in user and group in user["groups"]:
            return user
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return _has_group


@app.get("/login")
def login():
    response = responses.RedirectResponse(url="/")

    payload = {
        "user_id": "uzytkownik",
        "groups": [
            # "admin",
            "user",
        ],
    }
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")  # type: ignore
    response.set_cookie(key="jwt", value=encoded_jwt, httponly=True)

    return response


@app.get("/")
def index(
    has_group: dict = Depends(has_group("user")),
):
    return {"message": f"Hello on INDEX page, {has_group['user_id']}!"}


@app.get("/admin")
def admin(
    has_group: dict = Depends(has_group("admin")),
):
    return {"message": f"Hello on ADMIN page, {has_group['user_id']}!"}
