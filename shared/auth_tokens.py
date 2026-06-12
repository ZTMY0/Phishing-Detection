from datetime import datetime, timedelta, timezone
import bcrypt
from jose import JWTError, jwt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(uid: str, role: str, secret: str, expire_minutes: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    return jwt.encode({"sub": uid, "role": role, "type": "access", "exp": exp}, secret, algorithm="HS256")


def create_refresh_token(uid: str, role: str, secret: str, expire_days: int = 7) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=expire_days)
    return jwt.encode({"sub": uid, "role": role, "type": "refresh", "exp": exp}, secret, algorithm="HS256")


def decode_token(token: str, secret: str, expected_type: str | None = None) -> dict:
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError as exc:
        raise ValueError("invalid token") from exc
    if expected_type and payload.get("type") != expected_type:
        raise ValueError("invalid token type")
    if "sub" not in payload:
        raise ValueError("invalid token payload")
    return payload
