from fastapi import Request, HTTPException
from passlib.context import CryptContext
from passlib.exc import UnknownHashError
from itsdangerous import URLSafeSerializer, BadSignature, BadData
from sqlalchemy import text

from config import SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD
from database import get_db


# 兼容历史 pbkdf2_sha256，同时支持当前数据库里的 bcrypt: $2b$12$...
# 注意：第一个 scheme 会作为 hash_password() 默认生成格式。
# 为了兼容当前 admin 的 bcrypt，且后续统一 bcrypt，这里把 bcrypt 放第一位。
pwd_context = CryptContext(
    schemes=["bcrypt", "pbkdf2_sha256"],
    deprecated="auto",
)

serializer = URLSafeSerializer(SECRET_KEY, salt="domain-monitor-session")
COOKIE_NAME = "domain_monitor_session"
MAX_PASSWORD_LENGTH = 256


def normalize_password(password: str | None) -> str:
    return (password or "")[:MAX_PASSWORD_LENGTH]


def normalize_hash(password_hash: str | None) -> str:
    return str(password_hash or "").strip()


def hash_password(password: str | None) -> str:
    return pwd_context.hash(normalize_password(password))


def is_supported_password_hash(password_hash: str | None) -> bool:
    password_hash = normalize_hash(password_hash)
    if not password_hash:
        return False

    try:
        return pwd_context.identify(password_hash) is not None
    except Exception:
        return False


def verify_password(password: str | None, password_hash: str | None) -> bool:
    password_hash = normalize_hash(password_hash)
    if not password_hash:
        return False

    try:
        return pwd_context.verify(normalize_password(password), password_hash)
    except (UnknownHashError, ValueError, TypeError):
        return False


def create_session(user_id: int) -> str:
    return serializer.dumps({"user_id": int(user_id)})


def parse_session(token: str | None):
    if not token:
        return None

    try:
        data = serializer.loads(token)
    except (BadSignature, BadData, Exception):
        return None

    if not isinstance(data, dict):
        return None

    user_id = data.get("user_id")
    if not user_id:
        return None

    return {"user_id": user_id}


def get_current_user(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=307, headers={"Location": "/login"})

    data = parse_session(token)
    if not data:
        raise HTTPException(status_code=307, headers={"Location": "/login"})

    with get_db() as db:
        user = db.execute(
            text("""
                SELECT *
                FROM users
                WHERE id = :id
                  AND enabled = true
            """),
            {"id": data["user_id"]},
        ).mappings().fetchone()

    if not user:
        raise HTTPException(status_code=307, headers={"Location": "/login"})

    return user


def require_admin(user):
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")


def ensure_admin_user():
    """
    启动时确保管理员账号存在。

    行为：
    1. 如果 admin 不存在：创建 admin。
    2. 如果 admin 的 password_hash 为空、明文、损坏、未知格式：重置为配置里的 ADMIN_PASSWORD。
    3. 如果 admin 的 hash 是受支持格式：不覆盖，避免每次重启都重置密码。
    """

    with get_db() as db:
        row = db.execute(
            text("""
                SELECT id, username, password_hash, enabled
                FROM users
                WHERE username = :username
                LIMIT 1
            """),
            {"username": ADMIN_USERNAME},
        ).mappings().fetchone()

        if not row:
            db.execute(
                text("""
                    INSERT INTO users(username, password_hash, role, enabled)
                    VALUES (:username, :password_hash, 'admin', true)
                """),
                {
                    "username": ADMIN_USERNAME,
                    "password_hash": hash_password(ADMIN_PASSWORD),
                },
            )
            return

        if not is_supported_password_hash(row["password_hash"]):
            db.execute(
                text("""
                    UPDATE users
                    SET password_hash = :password_hash,
                        enabled = true
                    WHERE id = :id
                """),
                {
                    "id": row["id"],
                    "password_hash": hash_password(ADMIN_PASSWORD),
                },
            )
            return

        if not row["enabled"]:
            db.execute(
                text("""
                    UPDATE users
                    SET enabled = true
                    WHERE id = :id
                """),
                {"id": row["id"]},
            )