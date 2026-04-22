# Overview — Mental Model

## What problem ArkeAuth solves

The Arke ecosystem needs a way to authenticate users, scope them to projects (tenants), and check fine-grained permissions on every API call. ArkeAuth provides this by layering identity concepts on top of Arke's universal Unit model: a **User** is an Arke Unit stored in `:arke_system`, a **Member** is a project-scoped Unit that references a User, and **Permissions** are `arke_link` records connecting Members to Arkes.

This makes ArkeAuth suited to:
- Multi-tenant systems where each project has its own set of members and permission rules.
- Applications that need JWT-based stateless auth with refresh token rotation.
- Systems requiring OTP (one-time password) for two-factor or passwordless signin flows.

## The core abstractions

Everything in ArkeAuth is built from these concepts. Internalize them before reading anything else.

### 1. User — `ArkeAuth.Core.User`

A system-wide identity. Users live in the `:arke_system` project and are Arke Units with `arke_id: :user`. Fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `username` | string | yes | Login identifier |
| `email` | string | yes | Unique |
| `password_hash` | string | yes | Bcrypt hash (auto-generated from plaintext `password` on create) |
| `first_name` | string | no | |
| `last_name` | string | no | |
| `phone_number` | string | no | |
| `last_login` | datetime | no | |
| `first_access` | boolean | no | Default: `true` |

**Key behaviors:**
- On creation (`before_load`), the plaintext `password` field is hashed via bcrypt and stored as `password_hash`. The `password` key is deleted from the data — it never persists.
- On encoding (`before_struct_encode`), `password_hash` is stripped from the output — it never leaks to API responses or JWT tokens.

### 2. Member — `ArkeAuth.Core.Member`

A project-scoped identity. Members belong to the `arke_auth_member` Group and reference a system User via the `arke_system_user` field. The Group contains two built-in Arke types:

- **`super_admin`** — full permissions on everything, bypasses all permission checks.
- **`member_public`** — the baseline permission level; permissions assigned to `member_public` apply to all members.

**Lifecycle hooks (Group-level):**
- `before_unit_create` — if `arke_system_user` is a map (not a string ID), auto-creates the corresponding User in `:arke_system` first, then links the member.
- `before_unit_update` — if `arke_system_user` is a map, updates the underlying system User.
- `on_unit_delete` — cascade-deletes the associated system User.

This means creating a Member with inline user data (`%{arke_system_user: %{username: "ada", email: "ada@example.com", password: "secret"}}`) will automatically create the User record.

### 3. Guardian / JWT — `ArkeAuth.Guardian`, `ArkeAuth.SSOGuardian`

Token management is handled by [Guardian](https://github.com/ueberauth/guardian). ArkeAuth defines two Guardian modules:

| Module | Token subject | Lookup on decode | Use case |
|---|---|---|---|
| `ArkeAuth.Guardian` | Member (project-scoped) | `get_by(project: p, group_id: "arke_auth_member", id: id)` | Standard auth — most API calls |
| `ArkeAuth.SSOGuardian` | User (system-wide) | `get_by(project: :arke_system, arke_id: :user, id: id)` | SSO flows — cross-project auth |

**Token types:**
- **Access token** — short-lived (default: 7 days), used for API authentication.
- **Refresh token** — longer-lived (default: 30 days), exchanged for a new access + refresh token pair.

**What goes in the JWT:**
- `ArkeAuth.Guardian`: `%{id, project, email, first_name, last_name, subscription_active}` — member data, no password.
- `ArkeAuth.SSOGuardian`: `%{id, ...user.data}` minus `password_hash` — user data, no project context.

### 4. Permission — `ArkeAuth.Utils.Permission`

Permissions are stored as `arke_link` Units with `type: "permission"`. A link from a member type (or `member_public`) to an Arke carries permission flags in its `metadata`:

```
arke_link {
  parent_id: "super_admin" | "member_public" | "<member_arke_id>",
  child_id:  "<target_arke_id>",
  type:      "permission",
  metadata:  %{filter: nil, get: true, put: true, post: true, delete: true, child_only: false}
}
```

**Resolution order:**
1. If member is `super_admin` → `%{get: true, put: true, post: true, delete: true}` (bypass).
2. If member has `subscription_active: false` → `%{get: false, put: false, post: false, delete: false}` (locked out).
3. Otherwise: merge `member_public` permissions with member-specific permissions. Public permissions take precedence (if public says `true`, it stays `true`).
4. For impersonated members: further filtered by `ArkeAuth.Guardian[:allowed_methods]` config.

**Permission fields:**

| Field | Type | Meaning |
|---|---|---|
| `filter` | nil or expression | Row-level filter applied to queries |
| `get` | boolean | Read access |
| `put` | boolean | Update access |
| `post` | boolean | Create access |
| `delete` | boolean | Delete access |
| `child_only` | boolean | Restrict to child records only |

### 5. OTP — `ArkeAuth.Core.Otp`

One-time passwords for 2FA or passwordless signin. An OTP is an Arke Unit with `arke_id: :otp`:

| Field | Required | Notes |
|---|---|---|
| `code` | yes | 4-digit random string |
| `action` | yes | e.g. `"signin"`, `"password_reset"` |
| `expiry_datetime` | yes | UTC naive datetime |

**ID format:** `"otp_#{action}_#{member_id}"` — ensures one active OTP per action per member (old ones auto-deleted on generate).

**TTL:** configurable via `config :arke_auth, ArkeAuth.Otp, ttl: {5, :minutes}` (default: 5 minutes).

**Test bypass:** set `OTP_BYPASS_CODE` env var to skip real OTP lookup and return a fixed code.

### 6. Temporary Token — `ArkeAuth.Core.TemporaryToken`

Generic time-limited tokens for one-off operations (invitations, email verification, etc.):

| Field | Notes |
|---|---|
| `expiration_datetime` | Absolute expiration time |
| `is_reusable` | Whether the token can be used more than once |
| `link_member` | Optional: associated member (for auth tokens) |

**Default TTL:** `config :arke_auth, :temporary_token_expiration, 1800` (30 minutes in seconds).

### 7. Reset Password Token — `ArkeAuth.ResetPasswordToken`

Dedicated token for password reset flows:

| Field | Required | Notes |
|---|---|---|
| `token` | yes | 22-byte crypto-random, base64 URL-encoded |
| `user_id` | yes | Reference to the user |
| `expiration` | yes | Expiration datetime |

**TTL:** `config :arke_auth, :reset_password_token_ttl, weeks: 2` (default: 2 weeks).

Token is auto-generated in the `before_load` hook on create — you only need to provide `user_id`.

## Authentication flow

```
Client sends username + password
        │
        ▼
ArkeAuth.Core.Auth.validate_credentials(username, password, project)
        │
        ├─ 1. Look up User by username in :arke_system
        │     └─ Verify bcrypt password hash
        │
        ├─ 2. Look up Member by arke_system_user in target project
        │     └─ Check member is not inactive
        │
        ├─ 3. Format member data (strip password_hash)
        │
        └─ 4. Generate access + refresh tokens via Guardian
              └─ Return {:ok, member, access_token, refresh_token}
```

**Important:** authentication always verifies the User in `:arke_system`, then looks up the Member in the specified project. A User can exist in the system but not be a Member of the requested project — this returns `"unauthorized"`.

## Token refresh flow

```
Client sends refresh_token
        │
        ▼
ArkeAuth.Core.Auth.refresh_tokens(member, refresh_token)
        │
        ├─ 1. Decode and verify token has type "refresh"
        │
        ├─ 2. Exchange refresh → new access token (Guardian.exchange)
        │
        └─ 3. Generate new refresh token
              └─ Return {:ok, new_access_token, new_refresh_token}
```

## Authorization model

```
Request with JWT
        │
        ▼
Guardian.Plug decodes JWT → loads Member
        │
        ▼
ArkeAuth.Utils.Permission.get_member_permission(member, arke_id, project)
        │
        ├─ Query arke_link where parent_id IN [member_public, member.arke_id]
        │                   AND child_id = target_arke_id
        │                   AND type = "permission"
        │
        ├─ Merge public + member-specific permissions
        │
        └─ Return %{filter:, get:, put:, post:, delete:, child_only:}
```

The HTTP layer (`arke_server`) calls these permission functions in its plugs/controllers. ArkeAuth itself provides the permission logic but no HTTP middleware.

## Module map at a glance

```
┌─────────────────────────────────────────────────────┐
│              Your application / arke_server          │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
     ┌────────────────────┐
     │  ArkeAuth.Core.Auth│   ◄── login, tokens, password mgmt
     └─────────┬──────────┘
               │
       ┌───────┼────────┐
       ▼       ▼        ▼
  ┌────────┐ ┌───────┐ ┌─────────────────┐
  │Guardian│ │Core   │ │Utils            │
  │modules │ │ User  │ │  Permission     │
  │(JWT)   │ │ Member│ │  (authorization)│
  │        │ │ Otp   │ │                 │
  └────────┘ └───────┘ └─────────────────┘
               │
               ▼
        ┌─────────────┐
        │ arke (core)  │  ◄── QueryManager, ArkeManager, Units, Links
        └─────────────┘
```

## Scope boundary vs. sibling packages

| Concern | Where it lives |
|---|---|
| User/Member CRUD, password hashing, JWT tokens, permissions, OTP, reset tokens | **arke_auth** (this package) |
| Schema definition, validation, CRUD pipeline, query builder, link graph | `arke` |
| Postgres persistence (Ecto repo, migrations, SQL) | `arke_postgres` |
| HTTP routes, REST controllers, Guardian plugs | `arke_server` |

If you're working on something here and find yourself reaching for SQL, HTTP routes, or Phoenix plugs — you're in the wrong package.
