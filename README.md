# Dukaan Check - Local Shop Discovery and Product Availability
Flask + Supabase (Postgres) + Bootstrap. Roles: customer, shop owner, admin.

## Read this first (no sugar coating)
- Your **Project URL** and **publishable key** are NOT database credentials. This app needs the
  **database password** to talk to Supabase. Without it nothing works.
- The publishable key is public by design. Never use it for writes, and NEVER paste your
  `service_role` / secret key or database password in chat, GitHub or screenshots.
- Supabase's direct host (`db.<ref>.supabase.co`) is IPv6-only. Most hosts and many home
  networks are IPv4-only, so use the **Session pooler** string.

## 1. Get your database connection string
Supabase dashboard > your project > **Connect** > **Session pooler** > copy the URI.
It looks like `postgresql://postgres.pnzjspbseuwbirmqehdo:[YOUR-PASSWORD]@aws-0-<region>.pooler.supabase.com:5432/postgres`.
Forgot the password? Project Settings > Database > Reset database password.
If the password has symbols like `@ # / :`, URL-encode them (`@` = `%40`) or pick a simpler one.

## 2. Configure
1. Copy `env.example` to `.env` (exact name, with the dot).
2. Fill `SECRET_KEY` (command is inside the file) and `DATABASE_URL`.

## 3. Run locally (Python 3.10+)
```
python -m venv venv
venv\Scripts\activate          (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt
python setup_db.py             creates tables, locks them down, creates your admin login
python check_connection.py     must print only PASS lines
python app.py                  open http://127.0.0.1:5000
```
`check_connection.py` also proves your public key cannot read your data. If it prints
FAIL DATA LEAK, stop and re-run `setup_db.py`.

## 4. Deploy (Render, Railway, Koyeb: anything that reads a Procfile)
1. Push these files to a **private** GitHub repo (`.gitignore` already excludes `.env`).
2. New Web Service: build `pip install -r requirements.txt`, start command from `Procfile`.
3. Environment variables: `SECRET_KEY`, `DATABASE_URL`, `COOKIE_SECURE=1`, `BEHIND_PROXY=1`.
   Skipping `BEHIND_PROXY` makes the login limiter see one IP for everybody.
4. Health check path: `/healthz`.

## 5. Test flow
Register an owner > log in as admin and approve the shop > owner adds a product > register a
customer and search > set quantity 0 and confirm "Out of stock".

## Known limits
- One database connection per request. Fine for a college demo, not for thousands of users.
- Free Supabase projects pause after a week of inactivity. Restore from the dashboard.
- Login limiter is in memory (resets on restart, per worker).
