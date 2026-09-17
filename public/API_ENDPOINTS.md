# API endpoint map

| Method | Endpoint | Auth |
|---|---|---|
| GET | /api/health | Public |
| POST | /api/auth/login | Public |
| POST | /api/auth/logout | User |
| GET | /api/auth/status | User |
| POST | /api/auth/activate | Public |
| POST | /api/auth/validate-key | Public |
| GET | /api/admin/keys | Admin |
| GET | /api/admin/keys/:id | Admin |
| POST | /api/admin/keys | Admin |
| POST | /api/admin/keys/:id/revoke | Admin |
| POST | /api/admin/keys/:id/restore | Admin |
| GET | /api/admin/users | Admin |
| POST | /api/admin/users | Admin |
| PATCH | /api/admin/users/:id | Admin |
