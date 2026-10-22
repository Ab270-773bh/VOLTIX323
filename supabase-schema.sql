-- ZEKO CHARGE database starter for Supabase
-- Read README before running. Test in a new Supabase project first.
-- This schema is a foundation, not a complete payment-provider integration.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role text not null default 'customer' check (role in ('customer','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  name text not null,
  subtitle text not null default '',
  category text not null default 'ألعاب',
  description text not null default '',
  image_url text,
  base_price numeric(12,2),
  currency text not null default 'SYP',
  active boolean not null default true,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wallets (
  user_id uuid primary key references auth.users(id) on delete cascade,
  balance numeric(12,2) not null default 0 check (balance >= 0),
  currency text not null default 'SYP',
  updated_at timestamptz not null default now()
);

create table if not exists public.deposit_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric(12,2) not null check (amount > 0),
  currency text not null default 'SYP',
  payment_method text not null,
  payment_reference text,
  proof_url text,
  customer_note text,
  status text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  admin_note text,
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_name text not null,
  amount numeric(12,2) not null check (amount >= 0),
  currency text not null default 'SYP',
  player_identifier text,
  region text,
  customer_note text,
  status text not null default 'pending' check (status in ('pending','paid','processing','completed','failed','cancelled','refunded')),
  provider_order_id text,
  provider_response jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric(12,2) not null,
  currency text not null default 'SYP',
  type text not null check (type in ('deposit','purchase','refund','adjustment')),
  reference_id uuid,
  description text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  customer_name text not null default '',
  contact text not null default '',
  category text not null default 'general',
  subject text not null default '',
  message text not null,
  status text not null default 'open' check (status in ('open','in_progress','answered','closed')),
  admin_reply text,
  assigned_to uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists products_active_sort_idx on public.products(active, sort_order);
create index if not exists deposit_requests_user_created_idx on public.deposit_requests(user_id, created_at desc);
create index if not exists orders_user_created_idx on public.orders(user_id, created_at desc);
create index if not exists support_tickets_user_created_idx on public.support_tickets(user_id, created_at desc);

-- Create a profile + empty wallet when a user signs up.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles(id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name',''));
  insert into public.wallets(user_id, balance, currency) values (new.id, 0, 'SYP');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_zeko on auth.users;
create trigger on_auth_user_created_zeko
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Admins must be assigned manually from the Supabase SQL editor after creating your account.
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.wallets enable row level security;
alter table public.deposit_requests enable row level security;
alter table public.orders enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.support_tickets enable row level security;

-- Profiles: user can read/update their own non-role profile fields. No client role escalation.
drop policy if exists "profiles read own or admin" on public.profiles;
create policy "profiles read own or admin" on public.profiles for select
using (id = auth.uid() or public.is_admin());
drop policy if exists "profiles update own basic" on public.profiles;
create policy "profiles update own basic" on public.profiles for update
using (id = auth.uid()) with check (id = auth.uid());
drop policy if exists "profiles admin all" on public.profiles;
create policy "profiles admin all" on public.profiles for all
using (public.is_admin()) with check (public.is_admin());

-- Products: public can view active products; only admin can manage.
drop policy if exists "products public active read" on public.products;
create policy "products public active read" on public.products for select
using (active = true or public.is_admin());
drop policy if exists "products admin manage" on public.products;
create policy "products admin manage" on public.products for all
using (public.is_admin()) with check (public.is_admin());

-- Wallet balances are read-only to customers; updates are only via trusted server/admin workflows.
drop policy if exists "wallet read own" on public.wallets;
create policy "wallet read own" on public.wallets for select
using (user_id = auth.uid() or public.is_admin());
drop policy if exists "wallet admin manage" on public.wallets;
create policy "wallet admin manage" on public.wallets for all
using (public.is_admin()) with check (public.is_admin());

-- Customers can create their own deposit request, but cannot approve it.
drop policy if exists "deposit read own or admin" on public.deposit_requests;
create policy "deposit read own or admin" on public.deposit_requests for select
using (user_id = auth.uid() or public.is_admin());
drop policy if exists "deposit create own pending" on public.deposit_requests;
create policy "deposit create own pending" on public.deposit_requests for insert
with check (user_id = auth.uid() and status = 'pending');
drop policy if exists "deposit admin manage" on public.deposit_requests;
create policy "deposit admin manage" on public.deposit_requests for update
using (public.is_admin()) with check (public.is_admin());
drop policy if exists "deposit admin delete" on public.deposit_requests;
create policy "deposit admin delete" on public.deposit_requests for delete
using (public.is_admin());

-- Orders: customers can see and create their own pending requests. Admin can manage statuses.
drop policy if exists "orders read own or admin" on public.orders;
create policy "orders read own or admin" on public.orders for select
using (user_id = auth.uid() or public.is_admin());
drop policy if exists "orders create own pending" on public.orders;
create policy "orders create own pending" on public.orders for insert
with check (user_id = auth.uid() and status = 'pending');
drop policy if exists "orders admin update" on public.orders;
create policy "orders admin update" on public.orders for update
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "transactions read own or admin" on public.wallet_transactions;
create policy "transactions read own or admin" on public.wallet_transactions for select
using (user_id = auth.uid() or public.is_admin());
drop policy if exists "transactions admin insert" on public.wallet_transactions;
create policy "transactions admin insert" on public.wallet_transactions for insert
with check (public.is_admin());

drop policy if exists "support create ticket" on public.support_tickets;
create policy "support create ticket" on public.support_tickets for insert
with check (user_id is null or user_id = auth.uid());
drop policy if exists "support read own or admin" on public.support_tickets;
create policy "support read own or admin" on public.support_tickets for select
using (user_id = auth.uid() or public.is_admin());
drop policy if exists "support admin update" on public.support_tickets;
create policy "support admin update" on public.support_tickets for update
using (public.is_admin()) with check (public.is_admin());

-- IMPORTANT SECURITY NOTES:
-- 1) Never put Supabase service_role key or supplier API keys in browser code.
-- 2) Do not approve deposits or add wallet money based only on customer claims.
-- 3) Production approval/shipping should run through trusted server-side functions,
--    with atomic balance transactions and idempotency checks.
-- 4) Admin role is set manually by trusted project owner, not by the public website.
