import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from shared.config import get_settings
from shared.database import get_connection, init_schema, create_user, get_user_by_email
from shared.auth_tokens import hash_password

SEED = [
    ("admin@phishguard.com", "Admin1234!", "admin"),
    ("analyst@phishguard.com", "Analyst1234!", "analyst"),
    ("user@phishguard.com", "User1234!", "user"),
]

conn = get_connection(get_settings().database_path)
init_schema(conn)

for email, password, role in SEED:
    if get_user_by_email(conn, email):
        print(f"exists  {email}")
        continue
    create_user(conn, email, hash_password(password), role)
    print(f"created {email} ({role})")
