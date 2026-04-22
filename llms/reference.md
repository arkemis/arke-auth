# Reference — Public API Surface

Function-by-function reference for the modules you're likely to touch. Signatures reflect arke_auth 0.4.4 source. For each module, only public functions that callers use are listed; internal helpers are omitted.

## Module map

| Module | Role |
|---|---|
| `ArkeAuth.Core.Auth` | Orchestration: credential validation, token creation/refresh, password change |
| `ArkeAuth.Core.User` | User Arke definition + password hash/check/update |
| `ArkeAuth.Core.Member` | Member Group definition + cascade lifecycle hooks |
| `ArkeAuth.Core.Otp` | OTP Arke definition + code generation |
| `ArkeAuth.Core.TemporaryToken` | Temporary token Arke + generation helpers |
| `ArkeAuth.ResetPasswordToken` | Reset password token Arke + auto-generation on create |
| `ArkeAuth.Guardian` | Guardian callbacks for project-scoped member JWT |
| `ArkeAuth.SSOGuardian` | Guardian callbacks for system-level user JWT (SSO) |
| `ArkeAuth.Utils.Permission` | Permission resolution: public + member merge, super_admin bypass |
| `ArkeAuth.Boundary.OtpManager` | ETS-backed OTP manager: code retrieval + bypass |
| `ArkeAuth.Boundary.Validators` | Input validators (password field check) |
| `ArkeAuth.Application` | OTP application startup (supervises OtpManager) |

---

## `ArkeAuth.Core.Auth`

The main entry point. `arke_server`'s `AuthController` calls these functions.

### Credential validation

```elixir
Auth.validate_credentials(username, password, project \\ :arke_system)
# -> {:ok, member, access_token, refresh_token}
# -> {:error, [%{context: :auth, message: "unauthorized"}]}
```

1. Looks up User by `username` in `:arke_system`.
2. Verifies password via `Bcrypt.checkpw/2`.
3. Looks up Member in `project` via `group_id: "arke_auth_member"`, matched on `arke_system_user: user.id`.
4. Checks member is not inactive (`inactive != true`).
5. Formats member and creates access + refresh tokens.

### Token operations

```elixir
Auth.create_tokens(resource, sso \\ "default")
# -> {:ok, resource, access_token, refresh_token}
```

`sso` parameter: `"default"` uses `ArkeAuth.Guardian`, `"sso"` uses `ArkeAuth.SSOGuardian`.

```elixir
Auth.refresh_tokens(user, refresh_token)
# -> {:ok, new_access_token, new_refresh_token}
# -> {:error, [%{context: :auth, message: "invalid token"}]}
```

Validates the refresh token, exchanges it for a new access token via `Guardian.exchange/3`, then creates a fresh refresh token. Always uses `ArkeAuth.Guardian` (not SSO).

### Password management

```elixir
Auth.change_password(user, old_password, new_password)
# -> {:ok, %Unit{}}
# -> {:error, [%{context: :auth, message: "invalid password"}]}
```

Verifies old password, then updates via `User.update_password/2`.

### User update

```elixir
Auth.update(user, data)
# -> {:ok, %Unit{}}
# -> {:error, errors}
```

Delegates to `QueryManager.update/2`. Strips `password` from the data map if present — password changes must go through `change_password/3`.

### Member resolution

```elixir
Auth.get_project_member(project, user)
# -> {:ok, member}
# -> {:error, [%{context: :auth, message: "member not exists"}]}
# -> {:error, [%{context: :auth, message: "member_not_active"}]}
```

Queries by `group_id: "arke_auth_member"` and `arke_system_user: user.id`. Checks `inactive` flag.

```elixir
Auth.format_member(member)
# -> %{id:, arke_id:, arke_system_user:, data: %{email:, first_name:, last_name:, subscription_active:}, metadata:, inserted_at:, updated_at:}
```

Shapes member data for token encoding. Note: `updated_at` is set to `inserted_at` (not a typo in the source — the member's `updated_at` is intentionally frozen to insertion time in the token payload).

---

## `ArkeAuth.Core.User`

Arke definition (`use Arke.System`, `arke do end`).

### Lifecycle hooks

```elixir
User.before_load(data, :create)
# Hashes password → password_hash, deletes :password key
# Skips if data already has :arke_id (means it's loaded from DB)

User.before_struct_encode(_, unit)
# Strips :password_hash from unit.data before serialization
```

### Functions

```elixir
User.check_password(user, password)
# -> {:ok, user}
# -> {:error, [%{context: :auth, message: "invalid password"}]}
```

Verifies `password` against `user.data.password_hash` using `Bcrypt.checkpw/2`.

```elixir
User.update_password(user, new_password)
# -> {:ok, %Unit{}}
# -> {:error, errors}
```

Hashes `new_password` and calls `QueryManager.update(user, password_hash: hashed)`.

---

## `ArkeAuth.Core.Member`

Group definition (`use Arke.System.Group`, `group id: "arke_auth_member"`).

### Lifecycle hooks

These fire for Units of **any Arke that belongs to the `arke_auth_member` Group** (e.g. `:super_admin`, `:admin`, custom member types).

```elixir
before_unit_create(_arke, unit)
# If unit.data.arke_system_user is a map → creates User in :arke_system
# Replaces arke_system_user with the new User's ID
# If arke_system_user is a string → pass-through (User already exists)

before_unit_update(_arke, unit)
# If unit.data.arke_system_user is a map → updates the linked User
# Looks up old member to find the existing arke_system_user reference

on_unit_delete(_arke, unit)
# Cascade: deletes the linked User from :arke_system
# Queries by arke_id: :user, id: unit.data.arke_system_user
```

---

## `ArkeAuth.Core.Otp`

Arke definition (`arke id: :otp`).

```elixir
Otp.generate(project, id, action, expiry_datetime \\ nil)
# -> {:ok, %Unit{data: %{code: "1234", action: "signin", expiry_datetime: ...}}}
# -> {:error, errors}
```

- Generates a random 4-digit code (`Enum.random(1_000..9_999)`).
- ID is formatted as `"otp_#{action}_#{id}"`.
- Deletes any existing OTP with the same ID/action before creating.
- Default expiry: from `config :arke_auth, ArkeAuth.Otp, ttl: {5, :minutes}`, or 300 seconds if unconfigured.

```elixir
Otp.parse_otp_id(action, id)
# -> "otp_#{action}_#{id}"
```

---

## `ArkeAuth.Core.TemporaryToken`

Arke definition (`arke id: :temporary_token`).

```elixir
TemporaryToken.generate_token(project, duration \\ nil, is_reusable \\ false, opts \\ [])
# -> {:ok, %Unit{}}
# -> {:error, errors}
```

- `duration`: `nil` (uses config default), `%{days: N}`, `%{minutes: N}`, `%{days: N, minutes: M}`, or integer seconds.
- Default: `config :arke_auth, :temporary_token_expiration, 1800` (30 minutes).
- `opts`: additional keyword args passed to `QueryManager.create`.

```elixir
TemporaryToken.generate_auth_token(project, member, duration \\ nil, is_reusable \\ false, opts \\ [])
# -> {:ok, %Unit{}}
```

Same as `generate_token` but sets `link_member` to `member.id` (or `member_id` if passed directly as a value).

---

## `ArkeAuth.ResetPasswordToken`

Arke definition (`arke do end`).

### Lifecycle hooks

```elixir
ResetPasswordToken.before_load(data, :create)
# Auto-generates token: 22 bytes crypto-random, base64url-encoded
# Sets expiration from config :arke_auth, :reset_password_token_ttl (default: weeks: 2)
# Requires :user_id in the input data
```

No public functions — token generation is automatic on creation via `QueryManager.create`.

---

## `ArkeAuth.Guardian`

Guardian implementation (`use Guardian, otp_app: :arke_auth`).

```elixir
Guardian.get_member(conn, opts \\ [])
# -> %Unit{} (the current member) | nil
```

Options:
- `impersonate: true` — if `enable_impersonate` is configured, returns the impersonated member (from `:impersonate` key) with `impersonate: true` added to the map. Falls back to the real member if no impersonation token.

```elixir
Guardian.subject_for_token(member, _claims)
# -> {:ok, %{id:, project:, email:, first_name:, last_name:, subscription_active:}}
```

Encodes member data into the JWT `sub` claim.

```elixir
Guardian.resource_from_claims(claims)
# -> {:ok, %Unit{}}
# -> {:error, :unauthorized}
```

Decodes JWT claims, looks up the member via `get_by(project: project, group_id: "arke_auth_member", id: id)`. Rejects members with `inactive: true`.

### Standard Guardian functions (inherited)

```elixir
Guardian.encode_and_sign(resource, claims \\ %{}, opts \\ [])
Guardian.decode_and_verify(token, claims \\ %{}, opts \\ [])
Guardian.exchange(token, from_type, to_type, opts \\ [])
Guardian.Plug.current_resource(conn, opts \\ [])
```

---

## `ArkeAuth.SSOGuardian`

Guardian implementation for SSO (`use Guardian, otp_app: :arke_auth`).

```elixir
SSOGuardian.subject_for_token(user, _claims)
# -> {:ok, %{id:, ...user.data without password_hash}}
```

```elixir
SSOGuardian.resource_from_claims(claims)
# -> {:ok, %Unit{}}  (User from :arke_system)
# -> {:error, :unauthorized}
```

Looks up User by ID in `:arke_system` project. No project context — SSO tokens are system-wide.

---

## `ArkeAuth.Utils.Permission`

### Public permission (unauthenticated)

```elixir
Permission.get_public_permission(arke_id, project)
Permission.get_public_permission(arke_unit)
# -> {:ok, %{filter:, get:, put:, post:, delete:, child_only:}}
# -> {:error, nil}  (no permission defined)
```

Queries `arke_link` where `parent_id: "member_public"`, `child_id: arke_id`, `type: "permission"`.

### Member permission (authenticated)

```elixir
Permission.get_member_permission(member, arke_id, project)
Permission.get_member_permission(member, arke_unit)
# -> {:ok, %{filter:, get:, put:, post:, delete:, child_only:}}
# -> {:error, nil}
```

1. Queries `arke_link` where `parent_id IN ["member_public", member.arke_id]`.
2. Splits into public and member-specific results.
3. Merges: member-specific values override public when truthy.
4. Applies special rules:
   - `super_admin` → `%{get: true, put: true, post: true, delete: true}`.
   - `subscription_active: false` → `%{get: false, put: false, post: false, delete: false}`.
   - `impersonate: true` → intersected with `allowed_methods` from Guardian config.

---

## `ArkeAuth.Boundary.OtpManager`

ETS-backed manager (`use Arke.Boundary.UnitManager`, `manager_id(:otp)`).

```elixir
OtpManager.get_code(project, member, action \\ "signin")
# -> %{data: %{code: "1234", expiry_datetime: ...}}
# -> nil
```

If `OTP_BYPASS_CODE` env var is set (non-empty), returns a synthetic OTP with that code and a 5-minute expiry — skips DB lookup entirely.

```elixir
OtpManager.delete_otp(unit)
# -> {:ok, nil} | nil
```

Deletes an OTP Unit from the DB. No-op if the argument isn't a `%Unit{}` with project metadata.

---

## `ArkeAuth.Boundary.Validators`

```elixir
Validators.check_user_password(data)
# -> {:ok, password_string}
# -> {:error, [%{context: :password, message: "is required"}]}
```

Checks that `:password` key exists in the data map. Used by `User.before_load/2` during creation.

---

## Application config reference

| Key | Type | Purpose |
|---|---|---|
| `:arke_auth, ArkeAuth.Guardian` | keyword | Guardian config: `:issuer`, `:secret_key`, `:verify_issuer`, `:token_ttl`, `:enable_impersonate`, `:allowed_methods` |
| `:arke_auth, ArkeAuth.SSOGuardian` | keyword | Guardian config for SSO (same shape as above) |
| `:arke_auth, ArkeAuth.Otp` | keyword | OTP config: `ttl: {5, :minutes}` |
| `:arke_auth, :temporary_token_expiration` | integer | Default duration in seconds (default: 1800) |
| `:arke_auth, :reset_password_token_ttl` | keyword | Expiry shift (default: `weeks: 2`) — passed to `DatetimeHandler.shift_datetime` |

## Environment variables

| Var | Purpose |
|---|---|
| `OTP_BYPASS_CODE` | If set (non-empty), all OTP checks return this code instead of querying the DB. For testing/development. |

---

## What's NOT in this package

Search elsewhere for:
- Schema, CRUD pipeline, query builder, ETS managers → `arke`
- Ecto repo, migrations, SQL translation → `arke_postgres`
- HTTP routes, plug pipelines, AuthController, OAuth strategies, mailer → `arke_server`
- React / frontend components → frontend packages
