# Recipes — Common Tasks

Task-oriented snippets. Each recipe is self-contained; read [overview.md](overview.md) first for the mental model.

All recipes assume:
- `:arke` and `:arke_auth` applications started.
- `config :arke, persistence: %{...}` configured (see [index.md](index.md#minimum-you-need-to-use-it)).
- `config :arke_auth, ArkeAuth.Guardian, ...` configured.
- The `:arke_system` project seeded with User/Member/OTP arke definitions.

---

## Authenticate a user (login)

```elixir
alias ArkeAuth.Core.Auth

case Auth.validate_credentials("ada@example.com", "secret123", :my_project) do
  {:ok, member, access_token, refresh_token} ->
    # member is a %Unit{} from the arke_auth_member group
    # access_token and refresh_token are JWT strings
    {:ok, %{member: member, access: access_token, refresh: refresh_token}}

  {:error, errors} ->
    # errors: [%{context: :auth, message: "unauthorized"}]
    {:error, :unauthorized}
end
```

The third argument (`project`) determines which project's member is looked up. The password is always verified against the `:arke_system` User.

---

## Refresh tokens

```elixir
alias ArkeAuth.Core.Auth

# `member` is the formatted member map (from token or from Auth.format_member)
case Auth.refresh_tokens(member, old_refresh_token) do
  {:ok, new_access_token, new_refresh_token} ->
    # Return both to the client — old refresh token is no longer valid
    {:ok, %{access: new_access_token, refresh: new_refresh_token}}

  {:error, errors} ->
    # errors: [%{context: :auth, message: "invalid token"}]
    {:error, :invalid_token}
end
```

---

## Create a User (system-level)

```elixir
alias Arke.{QueryManager, Boundary.ArkeManager}

user_arke = ArkeManager.get(:user, :arke_system)

{:ok, user} = QueryManager.create(:arke_system, user_arke,
  username: "ada@example.com",
  email: "ada@example.com",
  password: "secret123",          # auto-hashed by before_load hook
  first_name: "Ada",
  last_name: "Lovelace"
)

# user.data.password_hash exists (bcrypt hash)
# user.data[:password] does NOT exist (stripped)
```

---

## Create a Member with inline User creation

```elixir
alias Arke.{QueryManager, Boundary.ArkeManager}

# Assuming :admin is an Arke in the arke_auth_member group
admin_arke = ArkeManager.get(:admin, :my_project)

{:ok, member} = QueryManager.create(:my_project, admin_arke,
  arke_system_user: %{
    "username" => "ada@example.com",
    "email" => "ada@example.com",
    "password" => "secret123",
    "first_name" => "Ada",
    "last_name" => "Lovelace"
  }
)

# The before_unit_create hook:
# 1. Creates the User in :arke_system
# 2. Replaces arke_system_user with the User's ID
```

---

## Create a Member for an existing User

```elixir
alias Arke.{QueryManager, Boundary.ArkeManager}

admin_arke = ArkeManager.get(:admin, :my_project)

{:ok, member} = QueryManager.create(:my_project, admin_arke,
  arke_system_user: "existing_user_id",
  email: "ada@example.com",
  first_name: "Ada",
  last_name: "Lovelace"
)
```

---

## Change a user's password

```elixir
alias ArkeAuth.Core.Auth

# user is a %Unit{arke_id: :user} from :arke_system
case Auth.change_password(user, "old_password", "new_password") do
  {:ok, updated_user} ->
    # Password hash updated in DB
    :ok

  {:error, errors} ->
    # "invalid password" if old_password doesn't match
    {:error, errors}
end
```

---

## Generate an OTP code

```elixir
alias ArkeAuth.Core.Otp

# Generate a signin OTP for a member
{:ok, otp_unit} = Otp.generate(:my_project, member.id, "signin")

otp_unit.data.code            # "4821" (random 4-digit string)
otp_unit.data.expiry_datetime # ~N[2026-04-22 15:35:00] (5 min from now)
otp_unit.id                   # "otp_signin_<member_id>"

# If an OTP already exists for this action+member, it's deleted first
```

---

## Verify an OTP code

```elixir
alias ArkeAuth.Boundary.OtpManager
alias ArkeAuth.Core.Otp

otp_id = Otp.parse_otp_id("signin", member.id)

case Arke.QueryManager.get_by(project: :my_project, arke: "otp", id: otp_id) do
  nil ->
    {:error, :otp_not_found}

  otp_unit ->
    cond do
      NaiveDateTime.compare(otp_unit.data.expiry_datetime, NaiveDateTime.utc_now()) == :lt ->
        OtpManager.delete_otp(otp_unit)
        {:error, :otp_expired}

      otp_unit.data.code == submitted_code ->
        OtpManager.delete_otp(otp_unit)
        {:ok, :verified}

      true ->
        {:error, :invalid_code}
    end
end
```

Alternatively, use `OtpManager.get_code/3` which handles bypass:

```elixir
case OtpManager.get_code(:my_project, member, "signin") do
  nil -> {:error, :otp_not_found}
  otp -> # check otp.data.code and otp.data.expiry_datetime
end
```

---

## Generate a temporary token

```elixir
alias ArkeAuth.Core.TemporaryToken

# Basic token (30-minute default)
{:ok, token_unit} = TemporaryToken.generate_token(:my_project)

# Custom duration
{:ok, token_unit} = TemporaryToken.generate_token(:my_project, %{days: 1})
{:ok, token_unit} = TemporaryToken.generate_token(:my_project, %{minutes: 15})
{:ok, token_unit} = TemporaryToken.generate_token(:my_project, 3600)  # seconds

# Reusable token
{:ok, token_unit} = TemporaryToken.generate_token(:my_project, nil, true)

# Auth token linked to a member
{:ok, token_unit} = TemporaryToken.generate_auth_token(:my_project, member, %{days: 7})
# token_unit.data.link_member == member.id
```

---

## Generate a password reset token

```elixir
alias Arke.{QueryManager, Boundary.ArkeManager}

reset_arke = ArkeManager.get(:reset_password_token, :arke_system)

{:ok, reset_unit} = QueryManager.create(:my_project, reset_arke,
  user_id: user.id
)

reset_unit.data.token      # "xK9m2..." (22-byte crypto-random, base64url)
reset_unit.data.expiration # ~N[2026-05-06 15:30:00] (2 weeks from now)
reset_unit.data.user_id    # the user's ID
```

Token is auto-generated by the `before_load` hook — you only provide `user_id`.

---

## Get the current member from a conn (in arke_server context)

```elixir
# In a controller or plug that has already run AuthPipeline:
member = ArkeAuth.Guardian.get_member(conn)

# With impersonation support:
member = ArkeAuth.Guardian.get_member(conn, impersonate: true)
# If impersonating, member has :impersonate => true added
```

---

## Check permissions for an Arke

```elixir
alias ArkeAuth.Utils.Permission

# Public (unauthenticated) permission
case Permission.get_public_permission("person", :my_project) do
  {:ok, %{get: true}} -> # public read allowed
  {:error, nil} -> # no public permission defined
end

# Member permission
case Permission.get_member_permission(member, "person", :my_project) do
  {:ok, %{get: true, post: true, put: false, delete: false, filter: nil}} ->
    # member can read and create, but not update or delete
    :ok

  {:ok, %{filter: "eq(owner_id,{{arke_member}})"}} ->
    # member has access, but scoped to their own records
    # {{arke_member}} is replaced by arke_server with the member's ID
    :ok

  {:error, nil} ->
    # no permission defined for this member type
    :forbidden
end
```

---

## Set up a permission link

Permissions are regular `arke_link` Units — create them via `LinkManager`:

```elixir
alias Arke.LinkManager

# Allow "admin" members to do everything on "person" Arke
LinkManager.add_node(:my_project,
  "admin",           # parent_id (the member arke_id)
  "person",          # child_id (the target arke_id)
  "permission",      # link type
  %{
    "get" => true,
    "post" => true,
    "put" => true,
    "delete" => true,
    "filter" => nil,
    "child_only" => false
  }
)

# Allow public read-only access to "article" Arke
LinkManager.add_node(:my_project,
  "member_public",   # special parent for public permissions
  "article",
  "permission",
  %{"get" => true, "post" => false, "put" => false, "delete" => false}
)

# Row-level scoping: editors can only see their own posts
LinkManager.add_node(:my_project,
  "editor",
  "post",
  "permission",
  %{
    "get" => true,
    "post" => true,
    "put" => true,
    "delete" => true,
    "filter" => "eq(owner_id,{{arke_member}})"
  }
)
```

---

## Configure Guardian for production

```elixir
# config/runtime.exs
config :arke_auth, ArkeAuth.Guardian,
  issuer: "arke_auth",
  secret_key: System.fetch_env!("GUARDIAN_SECRET"),
  verify_issuer: true,
  token_ttl: %{
    "access" => {1, :hour},
    "refresh" => {30, :days}
  }

# Optional: SSO Guardian (separate secret recommended)
config :arke_auth, ArkeAuth.SSOGuardian,
  issuer: "arke_auth",
  secret_key: System.fetch_env!("SSO_GUARDIAN_SECRET"),
  verify_issuer: true,
  token_ttl: %{
    "access" => {1, :hour},
    "refresh" => {30, :days}
  }
```

---

## Enable impersonation

```elixir
config :arke_auth, ArkeAuth.Guardian,
  issuer: "arke_auth",
  secret_key: "...",
  enable_impersonate: true,
  allowed_methods: %{
    get: true,
    post: false,
    put: false,
    delete: false
  }
```

When `enable_impersonate: true`, `Guardian.get_member(conn, impersonate: true)` will check for an impersonation token (set by `arke_server`'s `ImpersonateAuthPipeline`). The `allowed_methods` map restricts what the impersonated member can do — in this example, read-only.

---

## Configure OTP TTL

```elixir
# Default: 5 minutes
config :arke_auth, ArkeAuth.Otp,
  ttl: {10, :minutes}

# Or in seconds/days:
config :arke_auth, ArkeAuth.Otp,
  ttl: {300, :seconds}

config :arke_auth, ArkeAuth.Otp,
  ttl: {1, :days}
```

---

## Use OTP bypass for testing

Set the `OTP_BYPASS_CODE` environment variable:

```bash
OTP_BYPASS_CODE=0000 mix test
```

When set, `OtpManager.get_code/3` always returns `%{data: %{code: "0000", expiry_datetime: ...}}` without querying the database. This affects all projects and all actions — it's a global bypass.
