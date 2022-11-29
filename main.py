import random
from datetime import datetime, timedelta
from typing import Any, Dict
from fastapi import Depends, FastAPI, HTTPException, status, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import PlainTextResponse, StreamingResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from io import BytesIO
from PIL import Image, ImageOps


def miller_rabin_test(n, k=14):
    """n - number to check
       k - accuracy"""
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n == 1:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


SECRET_KEY = "a13e080eb375eb90d9976be965790a4cd23ea622c6189a1c772eb44e63f8c1c6"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_NUM = 9223372036854775807


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


class User(BaseModel):
    username: str
    password: str

    def __init__(self, **data: Any):
        data["password"] = get_password_hash(data["password"])
        super().__init__(**data)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


users_db: Dict[str, User] = {}


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    while True:  # heroku bug? dict sometimes appears as empty
        if users_db:
            break

    if username in users_db:
        user = users_db[username]
        return user


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/register", status_code=201)
async def register(username: str, password: str):
    user = User(username=username, password=password)
    users_db[username] = user
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/time", response_class=PlainTextResponse)
async def display_time(current_user: User = Depends(get_current_user)):
    if current_user:
        return f"Current time is: {datetime.now()}"


@app.get("/prime/{number}", response_class=PlainTextResponse)
async def is_prime(number: int):
    if number not in range(1, MAX_NUM):
        raise HTTPException(status_code=400, detail='Number out of range!')
    elif miller_rabin_test(number):
        return f"The number {number} is prime."
    else:
        return f"The number {number} is NOT prime."


@app.post("/picture/invert", responses={200: {"content": {"image/jpeg"}}})
async def create_upload_file(image: bytes = File(...)):
    image_bytes = BytesIO(image)
    stream = Image.open(image_bytes)
    work_stream = ImageOps.invert(stream)
    inverted_image = BytesIO()
    work_stream.save(inverted_image, 'jpeg')
    inverted_image.seek(0)
    image_bytes.close()
    return StreamingResponse(content=inverted_image, media_type="image/jpeg")
