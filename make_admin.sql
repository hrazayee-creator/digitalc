-- Run AFTER you created your admin user in Authentication -> Users.
-- Replace the email below with YOUR admin email, then Run.
insert into public.admins (user_id)
select id from auth.users where email = 'YOUR-EMAIL@example.com'
on conflict do nothing;

-- must return exactly 1 row:
select a.user_id, u.email from public.admins a join auth.users u on u.id = a.user_id;
