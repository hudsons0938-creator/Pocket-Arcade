-- =====================================================================
--  Pocket Arcade · Stickman Duel accounts
--  Paste this whole file into Supabase → SQL Editor → New query → Run.
--  Safe to run again later (it updates the functions in place).
--
--  Players sign up with a username + password (no email needed).
--  Everything goes through the sd_* functions below; the tables
--  themselves are locked so nobody can read or change them directly.
--
--  After you make your own account in the game, make yourself admin by
--  running this one line here in the SQL Editor (use your username):
--      select sd_make_admin('yourusername');
-- =====================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists sd_private;
revoke all on schema sd_private from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on schema sd_private from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on schema sd_private from authenticated'; end if;
end $$;

create table if not exists public.sd_players (
  id          uuid primary key default gen_random_uuid(),
  username    text not null unique check (username ~ '^[a-z0-9_]{3,16}$'),
  pass_hash   text not null,
  display     text not null default '',
  title       text not null default 'rookie',
  wins        int  not null default 0,
  kills       int  not null default 0,
  level       int  not null default 1,
  best        int  not null default 0,
  save        jsonb,
  saved_at    timestamptz,
  is_admin    boolean not null default false,
  hidden      boolean not null default false,
  fails       int not null default 0,
  locked_until timestamptz,
  created_at  timestamptz not null default now()
);
create table if not exists public.sd_sessions (
  token_hash text primary key,
  player     uuid not null references public.sd_players(id) on delete cascade,
  expires    timestamptz not null
);
create table if not exists public.sd_gifts (
  id          bigint generated always as identity primary key,
  to_player   uuid not null references public.sd_players(id) on delete cascade,
  kind        text not null,
  item        text,
  amount      int  not null default 0,
  note        text,
  from_player uuid references public.sd_players(id) on delete set null,
  created_at  timestamptz not null default now(),
  claimed_at  timestamptz
);
create index if not exists sd_gifts_open on public.sd_gifts(to_player) where claimed_at is null;
create index if not exists sd_sessions_player on public.sd_sessions(player);

-- Lock the tables: row level security on, no policies, no direct grants.
alter table public.sd_players  enable row level security;
alter table public.sd_sessions enable row level security;
alter table public.sd_gifts    enable row level security;
revoke all on public.sd_players, public.sd_sessions, public.sd_gifts from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on public.sd_players, public.sd_sessions, public.sd_gifts from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke all on public.sd_players, public.sd_sessions, public.sd_gifts from authenticated'; end if;
end $$;

-- ---------------------------------------------------------------- helpers (private)
create or replace function sd_private.hash_token(p text) returns text
language sql immutable set search_path = public, extensions as
$$ select encode(extensions.digest(coalesce(p, ''), 'sha256'), 'hex') $$;

create or replace function sd_private.uid(p_token text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v uuid;
begin
  select s.player into v from public.sd_sessions s
   where s.token_hash = sd_private.hash_token(p_token) and s.expires > now();
  if v is null then raise exception 'Please log in again.' using errcode = 'P0001'; end if;
  return v;
end $$;

create or replace function sd_private.admin_uid(p_token text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := sd_private.uid(p_token);
begin
  if not exists (select 1 from public.sd_players where id = v and is_admin) then
    raise exception 'Admins only.' using errcode = 'P0001'; end if;
  return v;
end $$;

create or replace function sd_private.new_session(p_player uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(extensions.gen_random_bytes(24), 'hex');
begin
  delete from public.sd_sessions where player = p_player and expires < now();
  insert into public.sd_sessions(token_hash, player, expires)
    values (sd_private.hash_token(t), p_player, now() + interval '90 days');
  return t;
end $$;

create or replace function sd_private.pid(p uuid) returns text
language sql immutable as $$ select left(md5(p::text), 12) $$;

create or replace function sd_private.me(p_player uuid) returns jsonb
language sql security definer set search_path = public, extensions as $$
  select jsonb_build_object('user', username, 'pid', sd_private.pid(id), 'name', display, 'title', title,
         'admin', is_admin, 'save', save, 'saved_at', saved_at)
    from public.sd_players where id = p_player
$$;

create or replace function sd_private.num(j jsonb, k text, mx int) returns int
language sql immutable as $$
  select case when jsonb_typeof(j -> k) = 'number'
              then least(greatest(floor((j ->> k)::numeric), 0), mx)::int else 0 end
$$;

create or replace function sd_private.clean(t text, n int) returns text
language sql immutable as $$
  select left(btrim(regexp_replace(coalesce(t, ''), '[^[:alnum:] _.!?-]', '', 'g')), n)
$$;

create or replace function sd_private.find(p_user text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v uuid;
begin
  select id into v from public.sd_players where username = lower(btrim(coalesce(p_user, '')));
  if v is null then raise exception 'No player named %.', p_user using errcode = 'P0001'; end if;
  return v;
end $$;

-- ---------------------------------------------------------------- player functions
create or replace function public.sd_signup(p_user text, p_pass text, p_name text default '', p_save jsonb default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u text := lower(btrim(coalesce(p_user, ''))); v uuid;
begin
  if u !~ '^[a-z0-9_]{3,16}$' then
    raise exception 'Usernames are 3-16 letters, numbers or _ (no spaces).' using errcode = 'P0001'; end if;
  if length(coalesce(p_pass, '')) < 6 or length(p_pass) > 72 then
    raise exception 'Passwords must be 6 to 72 characters.' using errcode = 'P0001'; end if;
  if p_save is not null and (jsonb_typeof(p_save) <> 'object' or octet_length(p_save::text) > 150000) then p_save := null; end if;
  begin
    insert into public.sd_players(username, pass_hash, display, save, saved_at)
    values (u, extensions.crypt(p_pass, extensions.gen_salt('bf', 8)),
            coalesce(nullif(sd_private.clean(p_name, 14), ''), u), p_save, case when p_save is null then null else now() end)
    returning id into v;
  exception when unique_violation then
    raise exception 'That username is taken.' using errcode = 'P0001';
  end;
  if p_save is not null then
    update public.sd_players set wins = sd_private.num(p_save, 'wins', 500000), kills = sd_private.num(p_save, 'ko', 5000000),
           level = greatest(1, sd_private.num(p_save, 'lvl', 5000))
     where id = v;
    update public.sd_players set best = wins * 10 + kills * 2 + level * 25 where id = v;
  end if;
  return sd_private.me(v) || jsonb_build_object('token', sd_private.new_session(v));
end $$;

create or replace function public.sd_login(p_user text, p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r public.sd_players;
begin
  select * into r from public.sd_players where username = lower(btrim(coalesce(p_user, '')));
  if r.id is null then return jsonb_build_object('error', 'Wrong username or password.'); end if;
  if r.locked_until is not null and r.locked_until > now() then
    return jsonb_build_object('error', 'Too many wrong tries. Wait a minute and try again.'); end if;
  if extensions.crypt(coalesce(p_pass, ''), r.pass_hash) <> r.pass_hash then
    update public.sd_players set fails = case when fails + 1 >= 8 then 0 else fails + 1 end,
      locked_until = case when fails + 1 >= 8 then now() + interval '1 minute' else locked_until end
     where id = r.id;
    return jsonb_build_object('error', 'Wrong username or password.');
  end if;
  update public.sd_players set fails = 0, locked_until = null where id = r.id;
  return sd_private.me(r.id) || jsonb_build_object('token', sd_private.new_session(r.id));
end $$;

create or replace function public.sd_session(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin return sd_private.me(sd_private.uid(p_token)); end $$;

create or replace function public.sd_logout(p_token text)
returns jsonb language sql security definer set search_path = public, extensions as $$
  delete from public.sd_sessions where token_hash = sd_private.hash_token(p_token);
  select '{}'::jsonb
$$;

create or replace function public.sd_save(p_token text, p_save jsonb, p_name text default '', p_title text default 'rookie')
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := sd_private.uid(p_token); adm boolean; t text := coalesce(p_title, 'rookie');
        w int; k int; l int; nm text := sd_private.clean(p_name, 14);
begin
  if p_save is null or jsonb_typeof(p_save) <> 'object' then raise exception 'Bad save.' using errcode = 'P0001'; end if;
  if octet_length(p_save::text) > 150000 then raise exception 'Save is too large.' using errcode = 'P0001'; end if;
  select is_admin into adm from public.sd_players where id = v;
  if t !~ '^[a-z]{1,20}$' or (t = 'admin' and not adm) then t := 'rookie'; end if;
  w := sd_private.num(p_save, 'wins', 500000);
  k := sd_private.num(p_save, 'ko', 5000000);
  l := greatest(1, sd_private.num(p_save, 'lvl', 5000));
  -- an admin rename waiting to be delivered wins over the name the game sends
  if exists (select 1 from public.sd_gifts where to_player = v and kind = 'rename' and claimed_at is null) then nm := ''; end if;
  update public.sd_players set save = p_save, saved_at = now(), title = t,
         display = coalesce(nullif(nm, ''), display),
         wins = w, kills = k, level = l, best = w * 10 + k * 2 + l * 25
   where id = v;
  return jsonb_build_object('saved_at', now());
end $$;

create or replace function public.sd_claim(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v uuid := sd_private.uid(p_token); out jsonb;
begin
  with c as (
    update public.sd_gifts set claimed_at = now()
     where to_player = v and claimed_at is null
    returning id, kind, item, amount, note)
  select coalesce(jsonb_agg(jsonb_build_object('kind', kind, 'item', item, 'amount', amount, 'note', note) order by id), '[]'::jsonb)
    into out from c;
  return out;
end $$;

create or replace function public.sd_leaderboard(p_board text default 'best')
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(x), '[]'::jsonb) from (
    select jsonb_build_object('id', sd_private.pid(id), 'nm', coalesce(nullif(display, ''), 'Player'), 'tt', title,
           'wins', wins, 'kills', kills, 'level', level, 'best', best) as x
      from public.sd_players
     where not hidden and (wins > 0 or kills > 0)
     order by case coalesce(p_board, 'best') when 'kills' then kills when 'level' then level
                                             when 'wins' then wins else best end desc, created_at
     limit 50) q
$$;

-- ---------------------------------------------------------------- admin functions
create or replace function public.sd_admin_find(p_token text, p_q text default '')
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare q text := '%' || replace(replace(replace(lower(coalesce(p_q, '')), '\', '\\'), '%', '\%'), '_', '\_') || '%'; out jsonb;
begin
  perform sd_private.admin_uid(p_token);
  select coalesce(jsonb_agg(x), '[]'::jsonb) into out from (
    select jsonb_build_object('user', username, 'name', display, 'title', title, 'level', level, 'wins', wins,
           'kills', kills, 'hidden', hidden, 'admin', is_admin, 'coins', sd_private.num(save, 'coins', 2000000000),
           'seen', saved_at) as x
      from public.sd_players
     where username like q or lower(display) like q
     order by coalesce(saved_at, created_at) desc limit 60) s;
  return out;
end $$;

create or replace function public.sd_admin_give(p_token text, p_user text, p_kind text, p_item text default null,
                                                p_amount int default 0, p_note text default '')
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := sd_private.admin_uid(p_token); n int; amt int := coalesce(p_amount, 0);
        it text := left(coalesce(p_item, ''), 40); nt text := sd_private.clean(p_note, 80);
begin
  if p_kind not in ('coins', 'levels', 'weapon', 'stick', 'title', 'relic', 'unlockall', 'maxup') then
    raise exception 'Unknown gift type.' using errcode = 'P0001'; end if;
  if p_kind = 'coins' then amt := least(greatest(amt, 1), 100000000);
  elsif p_kind = 'levels' then amt := least(greatest(amt, 1), 500);
  else amt := 0; end if;
  if p_kind in ('weapon', 'stick', 'title', 'relic') and it !~ '^[a-z0-9_]{1,40}$' then
    raise exception 'Pick an item to give.' using errcode = 'P0001'; end if;
  if coalesce(btrim(p_user), '') in ('', '*') then
    insert into public.sd_gifts(to_player, kind, item, amount, note, from_player)
      select id, p_kind, nullif(it, ''), amt, nt, me from public.sd_players;
  else
    insert into public.sd_gifts(to_player, kind, item, amount, note, from_player)
      values (sd_private.find(p_user), p_kind, nullif(it, ''), amt, nt, me);
  end if;
  get diagnostics n = row_count;
  return jsonb_build_object('sent', n);
end $$;

create or replace function public.sd_admin_rename(p_token text, p_user text, p_name text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := sd_private.admin_uid(p_token); v uuid := sd_private.find(p_user); nm text := sd_private.clean(p_name, 14);
begin
  if nm = '' then raise exception 'Type a new name.' using errcode = 'P0001'; end if;
  update public.sd_players set display = nm where id = v;
  update public.sd_gifts set claimed_at = now() where to_player = v and kind = 'rename' and claimed_at is null;
  insert into public.sd_gifts(to_player, kind, item, note, from_player) values (v, 'rename', nm, '', me);
  return jsonb_build_object('ok', true, 'name', nm);
end $$;

create or replace function public.sd_admin_hide(p_token text, p_user text, p_hidden boolean)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform sd_private.admin_uid(p_token);
  update public.sd_players set hidden = coalesce(p_hidden, false) where id = sd_private.find(p_user);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.sd_admin_password(p_token text, p_user text, p_pass text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v uuid;
begin
  perform sd_private.admin_uid(p_token);
  if length(coalesce(p_pass, '')) < 6 or length(p_pass) > 72 then
    raise exception 'Passwords must be 6 to 72 characters.' using errcode = 'P0001'; end if;
  v := sd_private.find(p_user);
  update public.sd_players set pass_hash = extensions.crypt(p_pass, extensions.gen_salt('bf', 8)), fails = 0, locked_until = null where id = v;
  delete from public.sd_sessions where player = v;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.sd_admin_role(p_token text, p_user text, p_admin boolean)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := sd_private.admin_uid(p_token); v uuid := sd_private.find(p_user);
begin
  if v = me and not coalesce(p_admin, false) then
    raise exception 'You cannot remove your own admin.' using errcode = 'P0001'; end if;
  update public.sd_players set is_admin = coalesce(p_admin, false) where id = v;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.sd_admin_gifts(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare out jsonb;
begin
  perform sd_private.admin_uid(p_token);
  select coalesce(jsonb_agg(x), '[]'::jsonb) into out from (
    select jsonb_build_object('to', p.username, 'kind', g.kind, 'item', g.item, 'amount', g.amount, 'note', g.note,
           'at', g.created_at, 'claimed', g.claimed_at is not null) as x
      from public.sd_gifts g join public.sd_players p on p.id = g.to_player
     order by g.id desc limit 40) s;
  return out;
end $$;

-- Run by hand in the SQL Editor only (not callable from the game).
create or replace function public.sd_make_admin(p_user text)
returns text language plpgsql security definer set search_path = public, extensions as $$
begin
  update public.sd_players set is_admin = true where id = sd_private.find(p_user);
  return 'Admin on for ' || lower(p_user);
end $$;

-- ---------------------------------------------------------------- who may call what
revoke all on all functions in schema sd_private from public;
revoke execute on function public.sd_make_admin(text) from public;
do $$ declare f text; r text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on all functions in schema sd_private from %I', r);
      execute format('revoke execute on function public.sd_make_admin(text) from %I', r);
      foreach f in array array[
        'sd_signup(text,text,text,jsonb)', 'sd_login(text,text)', 'sd_session(text)', 'sd_logout(text)',
        'sd_save(text,jsonb,text,text)', 'sd_claim(text)', 'sd_leaderboard(text)',
        'sd_admin_find(text,text)', 'sd_admin_give(text,text,text,text,int,text)', 'sd_admin_rename(text,text,text)',
        'sd_admin_hide(text,text,boolean)', 'sd_admin_password(text,text,text)', 'sd_admin_role(text,text,boolean)',
        'sd_admin_gifts(text)'] loop
        execute format('grant execute on function public.%s to %I', f, r);
      end loop;
    end if;
  end loop;
end $$;
