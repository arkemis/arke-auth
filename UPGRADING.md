# Upgrading arke_auth

## To the auth hardening release (from 0.4.x)

One-time codes, magic links and login links no longer live in the database,
password reset links are signed instead of stored, and password hashes are
peppered. Whoever reads or writes the database can no longer recover or forge
a credential: every check needs a secret that only the application holds.

### 1. New required configuration

`arke_auth` refuses to start without both secrets. Read them from the
environment (or a secret manager) in your application's `config/runtime.exs`:

```elixir
config :arke_auth, ArkeAuth.Utils.TokenCrypto,
  token_key: System.fetch_env!("ARKE_AUTH_TOKEN_KEY"),
  previous_keys: []

config :arke_auth, ArkeAuth.Core.Password,
  pepper: System.fetch_env!("ARKE_AUTH_PASSWORD_PEPPER")
```

- Each must be at least 32 bytes. Generate them with
  `:crypto.strong_rand_bytes(48) |> Base.encode64()`.
- Keep them apart from each other and from the Guardian `secret_key`.
- **Back up the pepper.** Losing or changing it locks out every user whose
  password was hashed with it. There is no rotation for the pepper.
- The token key can be rotated: set the new one as `token_key` and move the
  old one to `previous_keys`. Reset links signed with an old key keep working
  while the key is listed; codes and tokens looked up by digest (OTP
  codes and temporary tokens) are invalidated, which they tolerate because
  they are short-lived.

### 2. Optional configuration

| Setting | Default | Allowed | Checked |
|---|---|---|---|
| `config :arke_auth, ArkeAuth.Otp, digits:` | `4` | `4` or `6` | at startup |
| `config :arke_auth, ArkeAuth.Otp, resend_cooldown_seconds:` | `30` | integer ≥ 0 (`0` disables it) | at startup |
| `config :arke_auth, ArkeAuth.Otp, ttl:` | `{5, :minutes}` | `{n, :seconds \| :minutes \| :days}` | — |
| `config :arke_auth, ArkeAuth.Otp, max_attempts:` | `5` | positive integer | — |
| `config :arke_auth, ArkeAuth.Core.Auth, max_failed_logins:, lockout_seconds:` | `10`, `900` | `max_failed_logins: 0` disables the lockout | — |
| `config :arke_auth, :reset_password_token_ttl` | `[weeks: 2]` | `weeks`, `days`, `hours`, `minutes`, `seconds`; at most 2 weeks | at startup |
| `config :arke_auth, ArkeAuth.Core.Password, accept_legacy_hashes:` | `true` | `false` after `wrap_legacy_passwords` (see §3) | at each check |
| `config :arke_auth, :temporary_token_expiration` | `86_400` (seconds, 1 day) | at most 30 days | when a token is generated |

A value checked at startup that is out of range makes `arke_auth` refuse to
start; a temporary token duration over 30 days makes the generation return an
error.

### 3. What changes at deploy

- **Every existing credential stored in the database stops working**: OTP
  codes in flight, temporary tokens (magic links), reset password links and
  values in the member `auth_token` field. Users request a new code or link.
- OTP codes, temporary tokens and attempt counters live in an
  in-memory store shared by the connected nodes (`ArkeAuth.Boundary.TokenStore`,
  one owner registered with `:global`, a replica on every node). They survive
  the loss of a node, **not a restart of every node at once**: a single-node
  deploy loses them at each restart.
- Attempt limits (OTP guesses, login lockout, app review code) now hold for
  the whole cluster instead of once per node.
- Legacy password hashes (plain bcrypt) keep working and are re-hashed with
  the pepper at the next successful sign-in. **While they are accepted,
  whoever can write the database can set a bcrypt of a chosen password on any
  user and sign in.** Close it right after the deploy:
  1. back up the database and the pepper;
  2. `mix arke_auth.wrap_legacy_passwords` (counts) then
     `mix arke_auth.wrap_legacy_passwords --confirm`: every legacy hash
     becomes `"pepw$" <> salt <> HMAC(pepper, legacy_hash)`, which verifies
     the same password and cannot be forged without the pepper. Users notice
     nothing; wrapped hashes are re-hashed at the next sign-in too;
  3. set `accept_legacy_hashes: false` and deploy, so that a legacy hash
     written into the database later is refused.

  `mix arke_auth.password_status` counts the users by kind (`current`,
  `wrapped`, `legacy`, `invalid`).
- The `otp`, `temporary_token` and `reset_password_token` arkes and their
  parameters (`code`, `action`, `expiry_datetime`, `expiration_datetime`,
  `is_reusable`, `link_member`, `expiration`, `user_id`, `token`) left the
  registry. Projects seeded earlier still hold their definitions and old rows;
  remove them with the purge task of a later release, after a backup.

### 4. API changes

- `ArkeAuth.Core.Otp`
  - `generate/4` returns `{:error, [%{message: "otp resend too soon"}]}` within
    the resend cooldown.
  - It returns a map, not a unit: `%{id:, metadata: %{project:, subject:},
    data: %{code:, action:, expiry_datetime:}}`. `data.code` is the only place
    the clear code ever appears.
  - `generate_code/1` raises for lengths other than 4 or 6.
- `ArkeAuth.Boundary.OtpManager` is no longer a process, and `get_code/3` no
  longer returns the clear code of a real OTP (the bypass code still does).
- `ArkeAuth.Boundary.AttemptLimiter` is no longer a process; the API is
  unchanged.
- `ArkeAuth.Core.TemporaryToken`
  - `generate_auth_token/5` returns a map (`token.id` is the token,
    `token.data` holds `link_member`, `is_reusable`, `expiration_datetime` and
    the extra opts) and refuses durations over 30 days.
  - New: `verify/3` (optionally bound to a member), `consume/2`, `revoke/2`,
    `revoke_all_for_member/2`. Deleting or deactivating a member revokes its
    tokens.
  - `generate_token/4` (a token without a member) is deprecated.
  - The default duration is 1 day (it was 30 minutes).
  - A token signs in with `signin` passed either as `auth_token` or as
    `token`: both go through the same checks. The member `auth_token` field
    logs a deprecation when set and no longer signs in: generate a token
    whenever a `?token=` link is needed.
  - Tokens are not units any more: replace `QueryManager.get_by(arke_id:
    :temporary_token, ...)` with `TemporaryToken.verify/3` and
    `QueryManager.delete/2` with `TemporaryToken.revoke/2`.
- `ArkeAuth.ResetPasswordToken`: `issue/1` returns
  `{:ok, %{token:, expiration:, user_id:}}`, `verify/1` returns the user. A
  password change voids every earlier link.
- New `ArkeAuth.Core.Password` (`hash/1`, `verify/2`, `kind/1`, `wrap/1`) and
  `ArkeAuth.Utils.TokenCrypto`.

### 5. Checklist for known applications

- Every application: add `token_key` and `pepper` to `runtime.exs` and to the
  test config; back up the pepper.
- Every application, after the deploy: run
  `mix arke_auth.wrap_legacy_passwords --confirm` (after a backup), then set
  `accept_legacy_hashes: false`.
- Applications that build invitation links with `TemporaryToken` (e.g.
  bandit's `InvitedMember`): validate with `TemporaryToken.verify(project,
  token, member_id)` instead of `QueryManager.get_by`, close the invitation
  with `TemporaryToken.revoke/2`, and revoke the previous tokens when
  re-sending an invitation.
- Applications that store login links in the member `auth_token` field (e.g.
  reward / incentidirect-backend imports and exports): stop setting the field
  and call `TemporaryToken.generate_auth_token(project, member, %{days: 7})`
  (or the duration you need) each time a link is exported or mailed; put
  `token.id` in the `?token=` link. Tokens are single-use and cannot be read
  back.
- Tests that changed OTP codes through `QueryManager.update/2`: use
  `ArkeAuth.Core.Otp.put_code/5`.
