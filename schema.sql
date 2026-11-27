CREATE TABLE IF NOT EXISTS users (
  user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(10) NOT NULL CHECK (role IN ('customer','owner','admin')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON users (lower(email));

CREATE TABLE IF NOT EXISTS shops (
  shop_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id BIGINT NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
  shop_name VARCHAR(120) NOT NULL,
  address VARCHAR(255) NOT NULL,
  phone VARCHAR(10) NOT NULL,
  opening_hours VARCHAR(100) NOT NULL DEFAULT '',
  lat NUMERIC(9,6),
  lng NUMERIC(9,6),
  status VARCHAR(10) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS categories (
  category_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  category_name VARCHAR(60) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_category_name ON categories (lower(category_name));

CREATE TABLE IF NOT EXISTS products (
  product_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  product_name VARCHAR(150) NOT NULL,
  category_id BIGINT NOT NULL REFERENCES categories(category_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_product ON products (lower(product_name), category_id);

CREATE TABLE IF NOT EXISTS inventory (
  inventory_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(shop_id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
  price NUMERIC(10,2) NOT NULL CHECK (price > 0),
  quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (shop_id, product_id)
);
CREATE INDEX IF NOT EXISTS ix_inventory_product ON inventory (product_id);

CREATE TABLE IF NOT EXISTS enquiries (
  enquiry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  shop_id BIGINT NOT NULL REFERENCES shops(shop_id) ON DELETE CASCADE,
  product_id BIGINT REFERENCES products(product_id) ON DELETE SET NULL,
  message VARCHAR(500) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_enquiries_shop ON enquiries (shop_id);

-- SECURITY: Supabase exposes every public table to the internet through its REST API,
-- and your publishable key is public. Without these lines anyone could read the users
-- table (password hashes included). RLS with no policies = the API sees nothing.
-- This app connects with the database role, which bypasses RLS, so it is unaffected.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE shops ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE enquiries ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON users, shops, categories, products, inventory, enquiries FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON users, shops, categories, products, inventory, enquiries FROM authenticated;
  END IF;
END
$$;
