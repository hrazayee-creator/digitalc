-- ============================================================================
-- Digital card panel - database setup (run ONCE in Supabase: SQL Editor -> New query -> Run)
-- Security model: tables are locked (no direct access for anon/authenticated).
-- Everything goes through the functions below.
--   * visitors:  get_card(slug)            -> only ACTIVE, non-expired cards
--   * customers: edit_load/edit_save(key)  -> secret edit key (stored only as a SHA-256 hash)
--   * you:       admin_* functions         -> only users listed in public.admins
-- ============================================================================

create table if not exists public.admins (
  user_id uuid primary key
);

create table if not exists public.cards (
  id          uuid primary key default gen_random_uuid(),
  slug        text not null unique,
  key_hash    text not null unique,
  label       text not null default '',
  data        jsonb not null default '{}'::jsonb,
  active      boolean not null default false,
  expires_at  timestamptz,
  views       bigint not null default 0,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  constraint cards_slug_format check (slug ~ '^[a-z0-9][a-z0-9-]{2,29}$')
);

alter table public.cards  enable row level security;
alter table public.admins enable row level security;
revoke all on table public.cards  from anon, authenticated;
revoke all on table public.admins from anon, authenticated;

-- ---------------------------------------------------------------- helpers
create or replace function public._hash_key(p_key text)
returns text
language sql
immutable
set search_path = public
as $$
  select encode(sha256(convert_to(coalesce(p_key, ''), 'utf8')), 'hex');
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.admins a where a.user_id = auth.uid());
$$;

-- ---------------------------------------------------------------- visitors
create or replace function public.get_card(p_slug text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.cards%rowtype;
begin
  select * into r
  from public.cards c
  where c.slug = lower(btrim(p_slug))
    and c.active
    and (c.expires_at is null or c.expires_at > now());
  if not found then
    return null;
  end if;
  update public.cards set views = views + 1 where id = r.id;
  return r.data;
end;
$$;

-- ---------------------------------------------------------------- customers
create or replace function public.edit_load(p_key text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.cards%rowtype;
begin
  select * into r from public.cards c where c.key_hash = public._hash_key(p_key);
  if not found then
    return null;
  end if;
  return jsonb_build_object(
    'slug', r.slug,
    'label', r.label,
    'data', r.data,
    'active', r.active,
    'expires_at', r.expires_at
  );
end;
$$;

create or replace function public.edit_save(p_key text, p_data jsonb)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  if p_data is null or jsonb_typeof(p_data) is distinct from 'object' then
    raise exception 'bad data' using errcode = '22023';
  end if;
  if length(p_data::text) > 70000 then
    raise exception 'data too large' using errcode = '22023';
  end if;
  update public.cards c
     set data = p_data, updated_at = now()
   where c.key_hash = public._hash_key(p_key);
  get diagnostics n = row_count;
  return n = 1;
end;
$$;

-- ---------------------------------------------------------------- admin
create or replace function public.admin_create(p_label text default '', p_slug text default null, p_days integer default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_slug text;
  v_key  text;
  i      integer := 0;
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  if p_days is not null and p_days <= 0 then
    raise exception 'days must be positive' using errcode = '22023';
  end if;

  v_key := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');

  if p_slug is null or btrim(p_slug) = '' then
    loop
      v_slug := substr(replace(gen_random_uuid()::text, '-', ''), 1, 8);
      exit when not exists (select 1 from public.cards c where c.slug = v_slug);
      i := i + 1;
      if i > 20 then
        raise exception 'could not generate a slug' using errcode = '22023';
      end if;
    end loop;
  else
    v_slug := lower(btrim(p_slug));
    if v_slug !~ '^[a-z0-9][a-z0-9-]{2,29}$' then
      raise exception 'bad slug (3-30 chars: a-z 0-9 -)' using errcode = '22023';
    end if;
    if exists (select 1 from public.cards c where c.slug = v_slug) then
      raise exception 'slug already taken' using errcode = '23505';
    end if;
  end if;

  insert into public.cards (slug, key_hash, label, active, expires_at)
  values (
    v_slug,
    public._hash_key(v_key),
    coalesce(p_label, ''),
    false,
    case when p_days is null then null else now() + make_interval(days => p_days) end
  );

  return jsonb_build_object('slug', v_slug, 'key', v_key);
end;
$$;

create or replace function public.admin_list()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  return coalesce((
    select jsonb_agg(
             jsonb_build_object(
               'slug', c.slug,
               'label', c.label,
               'name', c.data->'v'->>0,
               'active', c.active,
               'expires_at', c.expires_at,
               'views', c.views,
               'created_at', c.created_at,
               'updated_at', c.updated_at
             )
             order by c.created_at desc
           )
    from public.cards c
  ), '[]'::jsonb);
end;
$$;

-- p_days extends the expiry (from now if expired / unset, otherwise from the current expiry)
create or replace function public.admin_update(
  p_slug text,
  p_active boolean default null,
  p_days integer default null,
  p_clear_expiry boolean default false,
  p_label text default null
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  update public.cards c
     set active = coalesce(p_active, c.active),
         label = coalesce(p_label, c.label),
         expires_at = case
           when p_clear_expiry then null
           when p_days is not null then greatest(now(), coalesce(c.expires_at, now())) + make_interval(days => p_days)
           else c.expires_at
         end
   where c.slug = lower(btrim(p_slug));
  get diagnostics n = row_count;
  return n = 1;
end;
$$;

create or replace function public.admin_reset_key(p_slug text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key text;
  n integer;
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  v_key := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  update public.cards c set key_hash = public._hash_key(v_key) where c.slug = lower(btrim(p_slug));
  get diagnostics n = row_count;
  if n <> 1 then
    raise exception 'card not found' using errcode = 'P0002';
  end if;
  return v_key;
end;
$$;

create or replace function public.admin_delete(p_slug text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  delete from public.cards c where c.slug = lower(btrim(p_slug));
  get diagnostics n = row_count;
  return n = 1;
end;
$$;

create or replace function public.admin_view(p_slug text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  d jsonb;
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  select c.data into d from public.cards c where c.slug = lower(btrim(p_slug));
  return d;
end;
$$;

create or replace function public.admin_export()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'not admin' using errcode = '42501';
  end if;
  return coalesce((select jsonb_agg(to_jsonb(c) order by c.created_at) from public.cards c), '[]'::jsonb);
end;
$$;

-- ---------------------------------------------------------------- permissions
revoke execute on function public._hash_key(text) from public, anon, authenticated;

revoke execute on function public.get_card(text)        from public, anon, authenticated;
revoke execute on function public.edit_load(text)       from public, anon, authenticated;
revoke execute on function public.edit_save(text, jsonb) from public, anon, authenticated;
revoke execute on function public.is_admin()            from public, anon, authenticated;
revoke execute on function public.admin_create(text, text, integer) from public, anon, authenticated;
revoke execute on function public.admin_list()          from public, anon, authenticated;
revoke execute on function public.admin_update(text, boolean, integer, boolean, text) from public, anon, authenticated;
revoke execute on function public.admin_reset_key(text) from public, anon, authenticated;
revoke execute on function public.admin_delete(text)    from public, anon, authenticated;
revoke execute on function public.admin_view(text)      from public, anon, authenticated;
revoke execute on function public.admin_export()        from public, anon, authenticated;

grant execute on function public.get_card(text)         to anon, authenticated;
grant execute on function public.edit_load(text)        to anon, authenticated;
grant execute on function public.edit_save(text, jsonb) to anon, authenticated;

grant execute on function public.is_admin()             to authenticated;
grant execute on function public.admin_create(text, text, integer) to authenticated;
grant execute on function public.admin_list()           to authenticated;
grant execute on function public.admin_update(text, boolean, integer, boolean, text) to authenticated;
grant execute on function public.admin_reset_key(text)  to authenticated;
grant execute on function public.admin_delete(text)     to authenticated;
grant execute on function public.admin_view(text)       to authenticated;
grant execute on function public.admin_export()         to authenticated;
