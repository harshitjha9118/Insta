# Insta-style Social Demo

Instagram-inspired independent social app UI. This is not Instagram and must not be used to collect Instagram credentials. Use only test accounts created on this demo.

## Deploy
- Upload all files to a NEW GitHub repository.
- Render Web Service: Build `npm install`, Start `npm start`.
- Set `DATABASE_URL`, `SESSION_SECRET` (32+ chars), `ADMIN_USERNAME`, `ADMIN_PASSWORD` (12+ chars), `NODE_ENV=production`.
- Use your own Neon PostgreSQL database.
- Never upload `.env` or share secrets.

## Admin Panel
Open `/admin.html` and log in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from Render environment variables. It lists demo accounts and login success/failure events. Admin can reset a demo user's password; the generated temporary password is shown once. Existing user passwords are never viewable because only password hashes are stored.
