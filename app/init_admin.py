from database import init_db
from auth import ensure_admin_user

init_db()
ensure_admin_user()
print("admin user initialized")
