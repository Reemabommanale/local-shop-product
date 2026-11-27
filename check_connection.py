"""Verifies the Supabase connection AND that your public key cannot read your data."""
import json
import sys
import urllib.error
import urllib.request

import psycopg2

from app import SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL, ConfigError, db_params

TABLES = ["users", "shops", "categories", "products", "inventory", "enquiries"]


def main():
    failed = False
    print("Project URL:", SUPABASE_URL)
    try:
        conn = psycopg2.connect(connect_timeout=10, **db_params())
    except ConfigError as e:
        sys.exit("FAIL config: %s" % e)
    except psycopg2.OperationalError as e:
        sys.exit("FAIL database connection: %s\nUse the Session pooler string from Supabase > Connect." % e)
    with conn.cursor() as c:
        c.execute("SELECT current_user")
        print("PASS database connection as role:", c.fetchone()[0])
        c.execute("SELECT tablename, rowsecurity FROM pg_tables "
                  "WHERE schemaname='public' AND tablename = ANY(%s)", (TABLES,))
        found = dict(c.fetchall())
    missing = [t for t in TABLES if t not in found]
    if missing:
        print("FAIL missing tables %s. Run: python setup_db.py" % missing)
        failed = True
    open_tables = [t for t, rls in found.items() if not rls]
    if open_tables:
        print("FAIL row level security is OFF for %s. Run: python setup_db.py" % open_tables)
        failed = True
    elif found:
        print("PASS row level security is ON for all tables")

    # Probe the public REST API with the publishable key. It must NOT return rows.
    for t in ("users", "shops"):
        req = urllib.request.Request("%s/rest/v1/%s?select=*&limit=1" % (SUPABASE_URL, t),
                                     headers={"apikey": SUPABASE_PUBLISHABLE_KEY})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                body = json.loads(r.read().decode() or "[]")
            if body:
                print("FAIL DATA LEAK: the public key can read %s. Run setup_db.py now." % t)
                failed = True
            else:
                print("PASS public key sees no rows in %s" % t)
        except urllib.error.HTTPError as e:
            print("PASS public key is blocked from %s (HTTP %s)" % (t, e.code))
        except Exception as e:
            print("WARN could not reach the REST API for %s: %s" % (t, e))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
