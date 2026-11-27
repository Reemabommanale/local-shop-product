"""Local Shop Discovery and Product Availability System (Flask + MySQL)."""
import math
import os
import re
import secrets
import time
from datetime import timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from markupsafe import Markup
from urllib.parse import urlparse

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_env_file():
    """Tiny .env reader so you do not need extra packages. Real env vars win."""
    path = os.path.join(BASE_DIR, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env_file()
DEBUG = os.environ.get("FLASK_DEBUG") == "1"
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    if not DEBUG:
        # A random per-process key silently breaks logins when gunicorn runs 2+ workers.
        raise RuntimeError(
            "SECRET_KEY is missing or shorter than 32 characters. Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\"")
    SECRET_KEY = secrets.token_hex(32)

# Your Supabase project. Both values are public by design (they ship in browsers).
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://pnzjspbseuwbirmqehdo.supabase.co").rstrip("/")
SUPABASE_PUBLISHABLE_KEY = os.environ.get(
    "SUPABASE_PUBLISHABLE_KEY", "sb_publishable_BLOhoDWEc3ezhLbUqag05g_Z5P0JX28")
PROJECT_REF = (urlparse(SUPABASE_URL).hostname or "").split(".")[0]

app = Flask(__name__, template_folder=BASE_DIR, static_folder=None)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)
if os.environ.get("BEHIND_PROXY") == "1":  # Render, Railway etc: trust one proxy hop
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IST = timezone(timedelta(hours=5, minutes=30))


class ConfigError(RuntimeError):
    pass


def db_params():
    """DATABASE_URL (Supabase pooler string) wins; else direct host from SUPABASE_URL + DB_PASSWORD."""
    sslmode = os.environ.get("DB_SSLMODE", "require")
    url = os.environ.get("DATABASE_URL", "").strip()
    if url:
        return dict(dsn=url, sslmode=sslmode)
    pw = os.environ.get("DB_PASSWORD", "")
    if not pw:
        raise ConfigError("Set DATABASE_URL (recommended) or DB_PASSWORD. See README.md.")
    return dict(host=os.environ.get("DB_HOST", "db.%s.supabase.co" % PROJECT_REF),
                port=int(os.environ.get("DB_PORT", "5432")),
                user=os.environ.get("DB_USER", "postgres"), password=pw,
                dbname=os.environ.get("DB_NAME", "postgres"), sslmode=sslmode)


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        conn = psycopg2.connect(cursor_factory=RealDictCursor, connect_timeout=10, **db_params())
        conn.autocommit = True
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def q(sql, args=(), one=False):
    with get_db().cursor() as c:
        c.execute(sql, args or None)
        return c.fetchone() if one else c.fetchall()


def ex(sql, args=()):
    with get_db().cursor() as c:
        c.execute(sql, args or None)


# ---------------------------------------------------------------- security
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_field"] = lambda: Markup(
    '<input type="hidden" name="_csrf" value="%s">' % csrf_token())
app.add_template_filter(
    lambda v: "\u20b9{:,.2f}".format(v) if v is not None else "-", "inr")
app.add_template_filter(
    lambda v: v.astimezone(IST).strftime("%d %b, %I:%M %p") if v else "-", "stamp")


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = (request.form.get("_csrf") or "").encode()
        real = (session.get("_csrf") or "").encode()
        if not real or not secrets.compare_digest(sent, real):
            abort(400)


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(self)"
    if "uid" in session:
        resp.headers["Cache-Control"] = "no-store"
    return resp


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if "uid" not in session:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco


FAILS = {}  # ip -> (count, first_failure_time); in-memory login throttle


def too_many_attempts(ip):
    n, t = FAILS.get(ip, (0, 0))
    if n and time.time() - t > 600:
        FAILS.pop(ip, None)
        return False
    return n >= 5


# -------------------------------------------------------------- validation
def clean(name, maxlen):
    return (request.form.get(name) or "").strip()[:maxlen]


def parse_price(v):
    try:
        d = Decimal((v or "").strip()).quantize(Decimal("0.01"))
    except InvalidOperation:
        return None
    if not d.is_finite():
        return None
    return d if Decimal("0.01") <= d <= Decimal("9999999.99") else None


def parse_qty(v):
    try:
        n = int((v or "").strip())
    except ValueError:
        return None
    return n if 0 <= n <= 1000000 else None


def parse_coord(v, limit):
    v = (v or "").strip()
    if not v:
        return None, True
    try:
        f = float(v)
    except ValueError:
        return None, False
    if math.isnan(f) or abs(f) > limit:
        return None, False
    return f, True


def read_shop_form():
    d = dict(shop_name=clean("shop_name", 120), address=clean("address", 255),
             phone=clean("phone", 20), opening_hours=clean("opening_hours", 100))
    err = []
    if len(d["shop_name"]) < 2:
        err.append("Enter the shop name.")
    if len(d["address"]) < 5:
        err.append("Enter the full shop address.")
    if not re.fullmatch(r"[6-9][0-9]{9}", d["phone"]):
        err.append("Enter a valid 10-digit mobile number (digits only).")
    d["lat"], ok1 = parse_coord(request.form.get("lat"), 90)
    d["lng"], ok2 = parse_coord(request.form.get("lng"), 180)
    if not (ok1 and ok2) or ((d["lat"] is None) != (d["lng"] is None)):
        err.append("Latitude and longitude must both be valid, or both empty.")
    return d, err


def haversine(lat1, lng1, lat2, lng2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


# ------------------------------------------------------------ public pages
@app.route("/")
def index():
    return render_template(
        "index.html",
        categories=q("SELECT * FROM categories ORDER BY category_name"),
        recent=q("SELECT s.shop_id, s.shop_name, p.product_name, i.price, i.quantity "
                 "FROM inventory i JOIN products p ON p.product_id=i.product_id "
                 "JOIN shops s ON s.shop_id=i.shop_id "
                 "WHERE s.status='approved' AND i.quantity>0 "
                 "ORDER BY i.updated_at DESC LIMIT 8"),
        shops=q("SELECT shop_id, shop_name, address, opening_hours FROM shops "
                "WHERE status='approved' ORDER BY created_at DESC LIMIT 12"))


@app.route("/search")
def search():
    term = (request.args.get("q") or "").strip()[:100]
    cat = request.args.get("category", type=int)
    sort = "distance" if request.args.get("sort") == "distance" else "price"
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    if lat is None or lng is None or not (-90 <= lat <= 90 and -180 <= lng <= 180):
        lat = lng = None
    results = []
    searched = bool(term or cat)
    if searched:
        sql = ("SELECT s.shop_id, s.shop_name, s.address, s.phone, s.lat, s.lng, "
               "p.product_name, i.price, i.quantity, i.updated_at "
               "FROM inventory i JOIN products p ON p.product_id=i.product_id "
               "JOIN shops s ON s.shop_id=i.shop_id WHERE s.status='approved'")
        args = []
        if term:
            esc = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND p.product_name ILIKE %s"
            args.append("%" + esc + "%")
        if cat:
            sql += " AND p.category_id=%s"
            args.append(cat)
        results = list(q(sql + " LIMIT 200", args))
        for r in results:
            r["dist"] = (haversine(lat, lng, float(r["lat"]), float(r["lng"]))
                         if lat is not None and r["lat"] is not None else None)

        def key(r):
            far = r["dist"] if r["dist"] is not None else 1e9
            if sort == "distance" and lat is not None:
                return (r["quantity"] <= 0, far, r["price"])
            return (r["quantity"] <= 0, r["price"], far)
        results.sort(key=key)
    return render_template("search.html", results=results, searched=searched,
                           term=term, cat=cat, sort=sort, lat=lat, lng=lng,
                           categories=q("SELECT * FROM categories ORDER BY category_name"))


@app.route("/shop/<int:shop_id>")
def shop(shop_id):
    s = q("SELECT * FROM shops WHERE shop_id=%s AND status='approved'",
          (shop_id,), one=True)
    if not s:
        abort(404)
    inv = q("SELECT i.product_id, p.product_name, c.category_name, i.price, "
            "i.quantity, i.updated_at FROM inventory i "
            "JOIN products p ON p.product_id=i.product_id "
            "JOIN categories c ON c.category_id=p.category_id "
            "WHERE i.shop_id=%s ORDER BY p.product_name", (shop_id,))
    return render_template("shop.html", s=s, inv=inv)


@app.route("/shop/<int:shop_id>/enquire", methods=["POST"])
@role_required("customer")
def enquire(shop_id):
    if not q("SELECT 1 FROM shops WHERE shop_id=%s AND status='approved'",
             (shop_id,), one=True):
        abort(404)
    msg = clean("message", 500)
    pid = request.form.get("product_id", type=int)
    if len(msg) < 5:
        flash("Write a message of at least 5 characters.", "danger")
        return redirect(url_for("shop", shop_id=shop_id))
    if pid and not q("SELECT 1 FROM inventory WHERE shop_id=%s AND product_id=%s",
                     (shop_id, pid), one=True):
        pid = None
    ex("INSERT INTO enquiries (customer_id, shop_id, product_id, message) "
       "VALUES (%s,%s,%s,%s)", (session["uid"], shop_id, pid, msg))
    flash("Enquiry sent to the shop.", "success")
    return redirect(url_for("shop", shop_id=shop_id))


# -------------------------------------------------------------------- auth
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    role = request.form.get("role")
    name, email = clean("name", 100), clean("email", 150).lower()
    pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
    errs, shop_data = [], None
    if role not in ("customer", "owner"):
        errs.append("Choose an account type.")
    if len(name) < 2:
        errs.append("Enter your name.")
    if not EMAIL_RE.match(email):
        errs.append("Enter a valid email address.")
    if not 8 <= len(pw) <= 128:
        errs.append("Password must be 8 to 128 characters.")
    if pw != pw2:
        errs.append("Passwords do not match.")
    if role == "owner":
        shop_data, e = read_shop_form()
        errs += e
    if not errs and q("SELECT 1 FROM users WHERE email=%s", (email,), one=True):
        errs.append("That email is already registered.")
    if errs:
        for e in errs:
            flash(e, "danger")
        return render_template("register.html")
    db = get_db()
    try:
        db.autocommit = False
        with db.cursor() as c:
            c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (%s,%s,%s,%s) "
                      "RETURNING user_id",
                      (name, email, generate_password_hash(pw, method="pbkdf2:sha256"), role))
            new_id = c.fetchone()["user_id"]
            if role == "owner":
                c.execute("INSERT INTO shops (owner_id,shop_name,address,phone,opening_hours,lat,lng) "
                          "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                          (new_id, shop_data["shop_name"], shop_data["address"],
                           shop_data["phone"], shop_data["opening_hours"],
                           shop_data["lat"], shop_data["lng"]))
        db.commit()
    except psycopg2.IntegrityError:
        db.rollback()
        flash("That email is already registered.", "danger")
        return render_template("register.html")
    except Exception:
        db.rollback()
        raise
    finally:
        db.autocommit = True
    flash("Account created. Log in to continue."
          + (" Your shop appears to customers after admin approval." if role == "owner" else ""),
          "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    ip = request.remote_addr or "?"
    if too_many_attempts(ip):
        flash("Too many failed attempts. Try again in 10 minutes.", "danger")
        return render_template("login.html"), 429
    user = q("SELECT * FROM users WHERE email=%s", (clean("email", 150).lower(),), one=True)
    if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
        FAILS.pop(ip, None)
        session.clear()
        session.permanent = True
        session.update(uid=user["user_id"], role=user["role"], name=user["name"])
        return redirect(url_for("dashboard"))
    n, t = FAILS.get(ip, (0, time.time()))
    FAILS[ip] = (n + 1, t)
    flash("Wrong email or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You are logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@role_required("customer", "owner", "admin")
def dashboard():
    return redirect(url_for({"owner": "owner_dashboard", "admin": "admin_dashboard"}
                            .get(session["role"], "index")))


# ------------------------------------------------------------------- owner
def my_shop():
    s = q("SELECT * FROM shops WHERE owner_id=%s", (session["uid"],), one=True)
    if not s:
        abort(404)
    return s


@app.route("/owner")
@role_required("owner")
def owner_dashboard():
    s = my_shop()
    inv = q("SELECT i.inventory_id, p.product_name, c.category_name, i.price, "
            "i.quantity, i.updated_at FROM inventory i "
            "JOIN products p ON p.product_id=i.product_id "
            "JOIN categories c ON c.category_id=p.category_id "
            "WHERE i.shop_id=%s ORDER BY p.product_name", (s["shop_id"],))
    enq = q("SELECT e.message, e.created_at, u.name AS customer, u.email AS customer_email, "
            "p.product_name FROM enquiries e JOIN users u ON u.user_id=e.customer_id "
            "LEFT JOIN products p ON p.product_id=e.product_id "
            "WHERE e.shop_id=%s ORDER BY e.created_at DESC LIMIT 50", (s["shop_id"],))
    in_stock = sum(1 for r in inv if r["quantity"] > 0)
    return render_template("owner.html", shop=s, inv=inv, enq=enq, total=len(inv),
                           in_stock=in_stock, out=len(inv) - in_stock,
                           categories=q("SELECT * FROM categories ORDER BY category_name"))


@app.route("/owner/product", methods=["POST"])
@role_required("owner")
def owner_add():
    s = my_shop()
    name = clean("product_name", 150)
    cid = request.form.get("category_id", type=int)
    price = parse_price(request.form.get("price"))
    qty = parse_qty(request.form.get("quantity"))
    if len(name) < 2:
        flash("Enter the product name.", "danger")
    elif not cid or not q("SELECT 1 FROM categories WHERE category_id=%s", (cid,), one=True):
        flash("Choose a category.", "danger")
    elif price is None:
        flash("Enter a valid price (0.01 to 9999999.99).", "danger")
    elif qty is None:
        flash("Enter a quantity between 0 and 1000000.", "danger")
    else:
        ex("INSERT INTO products (product_name, category_id) VALUES (%s,%s) "
           "ON CONFLICT DO NOTHING", (name, cid))
        p = q("SELECT product_id FROM products WHERE lower(product_name)=lower(%s) "
              "AND category_id=%s", (name, cid), one=True)
        ex("INSERT INTO inventory (shop_id, product_id, price, quantity) VALUES (%s,%s,%s,%s) "
           "ON CONFLICT (shop_id, product_id) DO UPDATE SET price=EXCLUDED.price, "
           "quantity=EXCLUDED.quantity, updated_at=now()",
           (s["shop_id"], p["product_id"], price, qty))
        flash("Product saved.", "success")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/product/<int:inv_id>/update", methods=["POST"])
@role_required("owner")
def owner_update(inv_id):
    s = my_shop()
    price = parse_price(request.form.get("price"))
    qty = parse_qty(request.form.get("quantity"))
    if price is None or qty is None:
        flash("Enter a valid price and quantity.", "danger")
    else:
        ex("UPDATE inventory SET price=%s, quantity=%s, updated_at=CURRENT_TIMESTAMP "
           "WHERE inventory_id=%s AND shop_id=%s", (price, qty, inv_id, s["shop_id"]))
        flash("Stock updated.", "success")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/product/<int:inv_id>/delete", methods=["POST"])
@role_required("owner")
def owner_delete(inv_id):
    s = my_shop()
    ex("DELETE FROM inventory WHERE inventory_id=%s AND shop_id=%s", (inv_id, s["shop_id"]))
    flash("Product removed from your shop.", "info")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/shop", methods=["POST"])
@role_required("owner")
def owner_shop():
    s = my_shop()
    d, errs = read_shop_form()
    if errs:
        for e in errs:
            flash(e, "danger")
    else:
        ex("UPDATE shops SET shop_name=%s, address=%s, phone=%s, opening_hours=%s, "
           "lat=%s, lng=%s WHERE shop_id=%s",
           (d["shop_name"], d["address"], d["phone"], d["opening_hours"],
            d["lat"], d["lng"], s["shop_id"]))
        flash("Shop profile updated.", "success")
    return redirect(url_for("owner_dashboard"))


# ------------------------------------------------------------------- admin
@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    def n(sql):
        return q(sql, one=True)["n"]
    stats = dict(
        customers=n("SELECT COUNT(*) AS n FROM users WHERE role='customer'"),
        shops=n("SELECT COUNT(*) AS n FROM shops"),
        pending=n("SELECT COUNT(*) AS n FROM shops WHERE status='pending'"),
        listings=n("SELECT COUNT(*) AS n FROM inventory"))
    return render_template(
        "admin.html", stats=stats,
        shops=q("SELECT s.*, u.name AS owner_name, u.email AS owner_email, "
                "(SELECT COUNT(*) FROM inventory i WHERE i.shop_id=s.shop_id) AS item_count "
                "FROM shops s JOIN users u ON u.user_id=s.owner_id "
                "ORDER BY CASE s.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, "
                "s.created_at DESC"),
        users=q("SELECT user_id, name, email, role, created_at FROM users "
                "ORDER BY created_at DESC LIMIT 200"),
        categories=q("SELECT * FROM categories ORDER BY category_name"))


@app.route("/admin/shop/<int:shop_id>/<action>", methods=["POST"])
@role_required("admin")
def admin_shop_action(shop_id, action):
    s = q("SELECT owner_id FROM shops WHERE shop_id=%s", (shop_id,), one=True)
    if not s or action not in ("approve", "reject", "delete"):
        abort(404)
    if action == "delete":  # removes owner account; shop and stock cascade
        ex("DELETE FROM users WHERE user_id=%s AND role='owner'", (s["owner_id"],))
        flash("Shop and owner account removed.", "info")
    else:
        ex("UPDATE shops SET status=%s WHERE shop_id=%s",
           ("approved" if action == "approve" else "rejected", shop_id))
        flash("Shop %s." % ("approved" if action == "approve" else "rejected"), "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def admin_user_delete(user_id):
    ex("DELETE FROM users WHERE user_id=%s AND role<>'admin'", (user_id,))
    flash("User removed.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/category", methods=["POST"])
@role_required("admin")
def admin_category():
    name = clean("category_name", 60)
    if len(name) < 2:
        flash("Enter a category name.", "danger")
    else:
        ex("INSERT INTO categories (category_name) VALUES (%s) ON CONFLICT DO NOTHING", (name,))
        flash("Category saved.", "success")
    return redirect(url_for("admin_dashboard"))


# ------------------------------------------------------------------ errors
MESSAGES = {400: "The request was invalid or your session expired. Go back, refresh and try again.",
            403: "You do not have access to this page.",
            404: "We could not find that page.",
            405: "That action is not allowed here.",
            413: "The submitted data was too large."}


def http_error(e):
    return render_template("error.html", code=e.code, msg=MESSAGES.get(e.code, e.name)), e.code


for _code in MESSAGES:
    app.register_error_handler(_code, http_error)


@app.errorhandler(psycopg2.OperationalError)
def db_down(_e):
    return render_template("error.html", code=503,
                           msg="The database is not reachable. Check DATABASE_URL and that Supabase is running."), 503


@app.errorhandler(ConfigError)
def config_missing(_e):
    return render_template("error.html", code=503,
                           msg="Database settings are missing on the server."), 503


@app.route("/healthz")
def healthz():
    return "ok"


@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500, msg="Something went wrong on our side."), 500


if __name__ == "__main__":
    app.run(debug=DEBUG)
