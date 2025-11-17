# JWT Attack Lab

Hands-on playground that pairs an intentionally broken JWT auth flow with a hardened implementation so you can reproduce classic attacks (alg none, weak secrets, token replay) and then demonstrate proper mitigations (strong HS256, refresh rotation, blacklisting).

## Project Structure

```
.
├─ backend   # Express API exposing insecure + secure JWT flows
└─ frontend  # React/Vite UI for running attacks and defenses
```

## Features

- **Insecure login**: `alg: none` tokens, weak HS256 secret (`password123`), no expiration, replayable.
- **Attack utilities**: token editor, brute-force weak secret, forge tokens, inspect payloads, replay tracking.
- **Secure login**: strong HS256 secrets, short-lived access tokens, refresh rotation, blacklist + mass revocation.
- **JWT inspector UI**: decode any token header/payload for demos.

## Prerequisites

- Node.js 18+ and npm

## Backend Setup

```bash
cd backend
npm install
npm run dev
```

The API listens on `http://localhost:4000`. Configure secrets via environment variables if desired:

```
ACCESS_TOKEN_SECRET=change-me
REFRESH_TOKEN_SECRET=change-me-too
PORT=4000
```

## Frontend Setup

```bash
cd frontend
npm install
cp .env.example .env   # optional: update VITE_API_BASE_URL
npm run dev
```

Vite prints the local URL (default `http://localhost:5173`). Ensure `VITE_API_BASE_URL` matches your backend origin.

## Demo Walkthrough

1. **Insecure login**  
   - Use `alice/alice123`, `bob/bob123`, or `admin/admin123`.  
   - Observe both tokens (`alg:none` + weak HS256) and note they never expire.

2. **Payload tampering**  
   - Change `role` to `admin` in the token editor and hit “Send to admin route” to bypass authorization.

3. **Replay attack**  
   - Click “Logout → replay attack”; send the same token again to prove it still works.

4. **Brute-force weak secret**  
   - Start the brute-force attack to recover `password123`, then forge a valid HS256 token with arbitrary claims.

5. **Secure flow**  
   - Log in under “Secure Login”; call the secure dashboard to show short-lived access tokens.  
   - Rotate refresh tokens and inspect the server-side store to see revoked sessions and blacklisted JTIs.  
   - Logout (single session or all) and verify old tokens now fail.

This script shows the full attack chain (modification, cracking, replay) followed by countermeasures (expiration, rotation, blacklist).

## Build for Production

```bash
# backend
cd backend && npm run start

# frontend
cd frontend && npm run build
```

Serve the frontend’s `dist/` folder behind your preferred static host, pointing `VITE_API_BASE_URL` at the deployed backend.

## Tech Stack

- Express 5, JSON Web Token, dayjs, uuid, bcrypt
- React + Vite
- Plain CSS (custom styles)

## License

MIT

