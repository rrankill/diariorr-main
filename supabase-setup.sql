insert into storage.buckets (id, name, public, allowed_mime_types)
values ('study-pdfs', 'study-pdfs', false, array['application/pdf'])
on conflict (id) do update
set public = false, allowed_mime_types = array['application/pdf'];

create table if not exists public.pdf_files (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  size bigint not null,
  storage_path text not null unique,
  user_id uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

alter table public.pdf_files enable row level security;

drop policy if exists "Authenticated users can list PDFs" on public.pdf_files;
create policy "Authenticated users can list PDFs"
on public.pdf_files for select to authenticated
using (true);

drop policy if exists "Users can register their own PDFs" on public.pdf_files;
create policy "Users can register their own PDFs"
on public.pdf_files for insert to authenticated
with check (auth.uid() = user_id);

drop policy if exists "Users can remove their own PDF records" on public.pdf_files;
create policy "Users can remove their own PDF records"
on public.pdf_files for delete to authenticated
using (auth.uid() = user_id);

drop policy if exists "Authenticated users can read PDF objects" on storage.objects;
create policy "Authenticated users can read PDF objects"
on storage.objects for select to authenticated
using (bucket_id = 'study-pdfs');

drop policy if exists "Users can upload their own PDF objects" on storage.objects;
create policy "Users can upload their own PDF objects"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'study-pdfs'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "Users can delete their own PDF objects" on storage.objects;
create policy "Users can delete their own PDF objects"
on storage.objects for delete to authenticated
using (
  bucket_id = 'study-pdfs'
  and (storage.foldername(name))[1] = auth.uid()::text
);

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'pdf_files'
  ) then
    alter publication supabase_realtime add table public.pdf_files;
  end if;
end
$$;

create table if not exists public.study_room (
  id boolean primary key default true check (id),
  admin_email text not null,
  admin_id uuid references auth.users(id),
  invite_token uuid
);

-- Replace this value with your administrator email before running the setup.
insert into public.study_room (id, admin_email)
values (true, 'rayanessanntana@gmail.com')
on conflict (id) do update
set admin_email = excluded.admin_email
where public.study_room.admin_id is null;

create table if not exists public.study_players (
  user_id uuid primary key references auth.users(id) on delete cascade,
  payload jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.study_room enable row level security;
alter table public.study_players enable row level security;

create or replace function public.is_study_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.study_players
    where user_id = auth.uid() and active
  );
$$;

drop policy if exists "Active study players can read active player records" on public.study_players;
create policy "Active study players can read active player records"
on public.study_players for select to authenticated
using (active and public.is_study_member());

drop policy if exists "Players can insert their own active record" on public.study_players;
create policy "Players can insert their own active record"
on public.study_players for insert to authenticated
with check (user_id = auth.uid() and active and public.is_study_member());

drop policy if exists "Players can update their own active record" on public.study_players;
create policy "Players can update their own active record"
on public.study_players for update to authenticated
using (user_id = auth.uid() and active and public.is_study_member())
with check (user_id = auth.uid() and active and public.is_study_member());

create or replace function public.claim_study_admin()
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_room public.study_room%rowtype;
  v_email text;
  v_confirmed boolean;
begin
  if auth.uid() is null then
    raise exception 'É necessário entrar com uma conta.';
  end if;

  select email, email_confirmed_at is not null
    into v_email, v_confirmed
    from auth.users
    where id = auth.uid();
  select * into v_room from public.study_room where id = true for update;

  if v_room.id is null or v_email is distinct from v_room.admin_email or not coalesce(v_confirmed, false) then
    raise exception 'A conta precisa ter o e-mail de administrador configurado e confirmado.';
  end if;
  if v_room.admin_id is not null and v_room.admin_id <> auth.uid() then
    raise exception 'Já existe outro administrador configurado.';
  end if;

  update public.study_room set admin_id = auth.uid() where id = true;
  insert into public.study_players (user_id, payload, active)
  values (auth.uid(), '{}'::jsonb, true)
  on conflict (user_id) do update set active = true;
  return true;
end;
$$;

create or replace function public.study_status()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_admin uuid;
  v_token uuid;
  v_member uuid;
  v_joined boolean;
  v_admin_email text;
  v_user_email text;
  v_email_confirmed boolean;
begin
  select admin_id, invite_token, admin_email into v_admin, v_token, v_admin_email
    from public.study_room where id = true;
  select email, email_confirmed_at is not null
    into v_user_email, v_email_confirmed
    from auth.users where id = auth.uid();
  v_email_confirmed := coalesce(v_email_confirmed, false);
  select exists (
    select 1 from public.study_players
    where user_id = auth.uid() and active
  ) into v_joined;
  select user_id into v_member
    from public.study_players
    where active and user_id <> v_admin
    limit 1;
  return jsonb_build_object(
    'joined', coalesce(v_joined, false),
    'is_admin', auth.uid() = v_admin,
    'can_claim_admin', coalesce(v_user_email = v_admin_email and v_email_confirmed, false),
    'member_id', v_member,
    'invite_token', case when auth.uid() = v_admin then v_token else null end
  );
end;
$$;

create or replace function public.create_study_invite()
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_admin uuid;
  v_token uuid;
begin
  select admin_id into v_admin from public.study_room where id = true for update;
  if v_admin is null or auth.uid() <> v_admin then
    raise exception 'Somente o administrador pode gerar convites.';
  end if;
  if exists (select 1 from public.study_players where active and user_id <> v_admin) then
    raise exception 'Remova o jogador atual antes de gerar outro convite.';
  end if;
  v_token := gen_random_uuid();
  update public.study_room set invite_token = v_token where id = true;
  return v_token;
end;
$$;

create or replace function public.join_study_invite(p_token uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_admin uuid;
  v_invite uuid;
  v_email_confirmed boolean;
begin
  if auth.uid() is null then
    raise exception 'É necessário entrar para aceitar o convite.';
  end if;
  select email_confirmed_at is not null into v_email_confirmed
    from auth.users where id = auth.uid();
  if not coalesce(v_email_confirmed, false) then
    raise exception 'Confirme o e-mail da conta antes de aceitar o convite.';
  end if;
  select admin_id, invite_token into v_admin, v_invite
    from public.study_room where id = true for update;
  if v_admin is null or v_invite is null or p_token <> v_invite then
    raise exception 'Este convite é inválido ou foi revogado.';
  end if;
  if auth.uid() = v_admin then
    return true;
  end if;
  if exists (
    select 1 from public.study_players
    where active and user_id <> v_admin and user_id <> auth.uid()
  ) then
    raise exception 'A vaga do segundo jogador já está ocupada.';
  end if;
  insert into public.study_players (user_id, payload, active)
  values (auth.uid(), '{}'::jsonb, true)
  on conflict (user_id) do update set active = true;
  return true;
end;
$$;

create or replace function public.remove_study_player(p_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_admin uuid;
begin
  select admin_id into v_admin from public.study_room where id = true for update;
  if v_admin is null or auth.uid() <> v_admin then
    raise exception 'Somente o administrador pode remover jogadores.';
  end if;
  if p_user_id = v_admin then
    raise exception 'O administrador não pode remover a própria conta.';
  end if;
  update public.study_players set active = false, updated_at = now()
    where user_id = p_user_id and active;
  if not found then
    raise exception 'Jogador ativo não encontrado.';
  end if;
  update public.study_room set invite_token = null where id = true;
  return true;
end;
$$;

revoke all on public.study_room, public.study_players from anon, authenticated;
grant select, insert, update on public.study_players to authenticated;
grant execute on function public.is_study_member() to authenticated;
grant execute on function public.claim_study_admin() to authenticated;
grant execute on function public.study_status() to authenticated;
grant execute on function public.create_study_invite() to authenticated;
grant execute on function public.join_study_invite(uuid) to authenticated;
grant execute on function public.remove_study_player(uuid) to authenticated;

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'study_players'
  ) then
    alter publication supabase_realtime add table public.study_players;
  end if;
end
$$;
