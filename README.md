# SKY KING OFC Authentication API Server

A lightweight REST API for an Android authentication app.

## Included functions

### User authentication
- Username/password login
- JWT session token
- Logout/revocation
- Current-user/status endpoint
- Admin user creation
- User enable/disable

### Activation keys
- Create keys with lifetime, 1/7/30/365 days or lifetime
- Activate a key for an installation/device ID
- Validate a key
- Device binding
- Expiry
- Revoke/disable keys
- List and inspect keys
- One-device limit by default

### Security
- Passwords hashed with bcrypt
- Activation keys stored as hashes
- JWT sessions
- Helmet security headers
- CORS configuration
- Basic rate limiting guidance
- No real secrets are embedded in the Android client

## Quick start

1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Change `JWT_SECRET` and `ADMIN_PASSWORD`.
4. Run:

```bash
npm install
npm run init-db
npm start
```

The API starts on `http://localhost:8080`.

For production, put it behind HTTPS using Caddy/Nginx/a cloud load balancer.

## Default admin

The values come from `.env`:
- username: `ADMIN_USERNAME`
- password: `ADMIN_PASSWORD`

Change them before deployment.

## API

### Login
`POST /api/auth/login`

```json
{"username":"admin","password":"your-password"}
```

Returns a JWT.

### Logout
`POST /api/auth/logout`

Header:
`Authorization: Bearer <token>`

### Status
`GET /api/auth/status`

Header:
`Authorization: Bearer <token>`

### Create activation key
`POST /api/admin/keys`

Header:
`Authorization: Bearer <admin-token>`

```json
{"name":"SKY-KING-001","durationDays":30,"deviceLimit":1}
```

Use `durationDays: 0` for lifetime.

### Activate
`POST /api/auth/activate`

```json
{"key":"SKY-KING-....","deviceId":"installation-generated-id"}
```

### Validate
`POST /api/auth/validate-key`

```json
{"key":"SKY-KING-....","deviceId":"installation-generated-id"}
```

### Revoke
`POST /api/admin/keys/:id/revoke`

### List keys
`GET /api/admin/keys`

### Key details
`GET /api/admin/keys/:id`

### Create user
`POST /api/admin/users`

```json
{"username":"user1","password":"StrongPassword123","role":"user"}
```

### Disable/enable user
`PATCH /api/admin/users/:id`

```json
{"enabled":false}
```

### List users
`GET /api/admin/users`

## Android integration

The Android app should send username/password and activation-key requests only over HTTPS. Generate a random installation ID and store it locally; don't rely on IMEI, serial number, or other restricted hardware identifiers.

The API is the authority. Do not put the admin password, JWT secret, or database credentials in the APK.
