"""One-time setup: creates tables (with RLS lockdown), categories and the admin account."""
import getpass
import os
import sys

import psycopg2
from werkzeug.security import generate_password_hash

from app import BASE_DIR, EMAIL_RE, ConfigError, db_params

CATEGORIES = ["Electronics", "Mobile Accessories", "Grocery", "Stationery", "Clothing", "Hardware"]


def main():
    try:
        conn = psycopg2.connect(connect_timeout=10, **db_params())
    except ConfigError as e:
        sys.exit(str(e))
    except psycopg2.OperationalError as e:
        sys.exit("Cannot connect to Supabase: %s\nCheck DATABASE_URL (use the Session pooler string)." % e)
    conn.autocommit = True
    with conn.cursor() as c:
        with open(os.path.join(BASE_DIR, "schema.sql"), encoding="utf-8") as f:
            c.execute(f.read())
        for cat in CATEGORIES:
            c.execute("INSERT INTO categories (category_name) VALUES (%s) ON CONFLICT DO NOTHING", (cat,))
        c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
        if c.fetchone()[0]:
            print("Tables are up to date. Admin already exists.")
            return
        print("Create the admin account")
        admin_name = input("Name: ").strip() or "Admin"
        email = input("Email: ").strip().lower()
        if not EMAIL_RE.match(email):
            sys.exit("Invalid email.")
        pw = getpass.getpass("Password (min 8 chars): ")
        if len(pw) < 8 or pw != getpass.getpass("Repeat password: "):
            sys.exit("Passwords must match and be at least 8 characters.")
        c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (%s,%s,%s,'admin')",
                  (admin_name, email, generate_password_hash(pw, method="pbkdf2:sha256")))
    print("Done. Now run: python check_connection.py")


if __name__ == "__main__":
    main()
