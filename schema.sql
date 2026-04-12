-- NEP Funeral Services Database Schema
-- Run this in Supabase SQL Editor

-- Staff / Users
CREATE TABLE IF NOT EXISTS staff (
  id SERIAL PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  role TEXT NOT NULL DEFAULT 'Agent',
  branch TEXT,
  permissions JSONB DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  last_login TIMESTAMPTZ,
  login_count INT DEFAULT 0
);

-- Members
CREATE TABLE IF NOT EXISTS members (
  id SERIAL PRIMARY KEY,
  member_no TEXT UNIQUE NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  id_number TEXT,
  phone TEXT,
  email TEXT,
  village TEXT,
  plan TEXT,
  branch TEXT,
  amount NUMERIC(10,2) DEFAULT 0,
  status TEXT DEFAULT 'Active',
  last_pay TEXT,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  beneficiaries JSONB DEFAULT '[]',
  pay_history JSONB DEFAULT '[]',
  pay_score INT DEFAULT 100,
  overdue_count INT DEFAULT 0
);

-- Claims
CREATE TABLE IF NOT EXISTS claims (
  id SERIAL PRIMARY KEY,
  claim_no TEXT UNIQUE NOT NULL,
  member_id INT REFERENCES members(id),
  member_name TEXT,
  plan TEXT,
  type TEXT,
  status TEXT DEFAULT 'Pending',
  amount NUMERIC(10,2) DEFAULT 0,
  notes TEXT,
  date TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Payments
CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  member_id INT REFERENCES members(id),
  member_name TEXT,
  plan TEXT,
  amount NUMERIC(10,2) NOT NULL,
  reference TEXT,
  date TEXT,
  channel TEXT,
  recorded_by INT REFERENCES staff(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  assignee_id INT REFERENCES staff(id),
  assignee_name TEXT,
  priority TEXT DEFAULT 'medium',
  status TEXT DEFAULT 'todo',
  category TEXT DEFAULT 'Other',
  due_date DATE,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Plans
CREATE TABLE IF NOT EXISTS plans (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  fee NUMERIC(10,2) NOT NULL,
  cashback NUMERIC(10,2) DEFAULT 0,
  grocery BOOLEAN DEFAULT FALSE,
  max_members INT DEFAULT 10,
  wait_months INT DEFAULT 3,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Funeral Cases
CREATE TABLE IF NOT EXISTS funerals (
  id SERIAL PRIMARY KEY,
  case_no TEXT UNIQUE NOT NULL,
  deceased_name TEXT NOT NULL,
  client_type TEXT DEFAULT 'walkin',
  package TEXT,
  package_price NUMERIC(10,2) DEFAULT 0,
  income NUMERIC(10,2) DEFAULT 0,
  cover_amount NUMERIC(10,2) DEFAULT 0,
  topup NUMERIC(10,2) DEFAULT 0,
  member_id INT REFERENCES members(id),
  contact_name TEXT,
  contact_phone TEXT,
  notes TEXT,
  dod TEXT,
  funeral_date TEXT,
  budget_lines JSONB DEFAULT '[]',
  budget_total NUMERIC(10,2) DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- Funeral Ledger (income + expenses per case)
CREATE TABLE IF NOT EXISTS funeral_ledger (
  id SERIAL PRIMARY KEY,
  funeral_id INT REFERENCES funerals(id),
  type TEXT NOT NULL, -- 'income' or 'expense'
  description TEXT,
  amount NUMERIC(10,2) NOT NULL,
  budgeted NUMERIC(10,2) DEFAULT 0,
  variance NUMERIC(10,2),
  category TEXT,
  supplier TEXT,
  reference TEXT,
  budget_line_idx INT,
  recorded_by INT REFERENCES staff(id),
  recorded_by_name TEXT,
  date TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Activity Log
CREATE TABLE IF NOT EXISTS activity_log (
  id SERIAL PRIMARY KEY,
  staff_id INT REFERENCES staff(id),
  user_name TEXT,
  action TEXT,
  detail TEXT,
  level TEXT DEFAULT 'info',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default owner account (password: nep2024)
INSERT INTO staff (first_name, last_name, username, password_hash, email, phone, role, branch, permissions, status)
VALUES (
  'Owner', 'Account', 'admin',
  '$2a$10$rOkMwGBX3Gp1234567890uQK8vN9AbCdEfGhIjKlMnOpQrStUvWx2',
  'admin@nepfuneralservices.co.za',
  '015 023 1712',
  'Owner',
  'Matangari (HQ)',
  '["all"]',
  'active'
) ON CONFLICT (username) DO NOTHING;

-- Insert default plans
INSERT INTO plans (name, fee, cashback, grocery, max_members, wait_months) VALUES
  ('Gold', 100, 0, false, 10, 3),
  ('Gold Plus', 170, 500, true, 10, 3),
  ('Platinum', 120, 0, false, 10, 3),
  ('Platinum Plus', 210, 750, true, 10, 3),
  ('Diamond', 140, 0, false, 10, 3),
  ('Diamond Plus', 250, 1000, true, 10, 3),
  ('Diamond Exclusive', 280, 1500, true, 10, 3)
ON CONFLICT (name) DO NOTHING;
