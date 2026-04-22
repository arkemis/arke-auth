# Gotchas — Sharp Edges

Operational surprises you'll hit when working with arke_auth. These are distinct from design rationale (see [design.md](design.md) for the "why"); this file is the "what trips people up."

---

## Member delete cascades to User

`ArkeAuth.Core.Member.on_unit_delete/2` deletes the associated User from `:arke_system` whenever a Member is deleted.

**Why it trips people up:** if a User belongs to multiple projects (has Members in each), deleting one project's Member wipes the shared User. All other Members referencing that User become orphaned — they'll fail to authenticate because the User no longer exists.

**What to do:** before deleting a Member, check if the User is referenced by Members in other projects. If so, only remove the Member record (bypass the Group hook) or reassign the other Members first. There's currently no built-in guard for this.

---

## "unauthorized" hides the real error

`Auth.validate_credentials/3` returns `{:error, "unauthorized"}` for all of these distinct failure modes:
- Username not found in `:arke_system`.
- Password doesn't match.
- User exists but is not a Member of the requested project.
- Member exists but is inactive (`inactive: true`).

The only slightly different error is `"member_not_active"` for inactive members (from `get_project_member/2`), but the outer `validate_credentials` wraps even that into `"unauthorized"`.

**What to do:** if you need to distinguish failure reasons (e.g. for user-facing error messages), call the internal steps separately: `get_by_username/2`, `verify_password/2`, `get_project_member/2`. These are private in the source, so you'd need to replicate the logic or add public wrappers.

---

## Auth.update strips password silently

`Auth.update/2` calls `check_password_data/1`, which deletes the `:password` key from the data map if present. This means you **cannot** change a password via `Auth.update/2` — you must use `Auth.change_password/3`.

**What trips people up:** calling `Auth.update(user, %{password: "new_pass"})` succeeds with no error, but the password is unchanged.

**What to do:** always use `Auth.change_password/3` for password changes. Use `Auth.update/2` only for non-password fields.

---

## Refresh token exchange is Guardian-only

`Auth.refresh_tokens/2` hardcodes `ArkeAuth.Guardian` for token verification and exchange. SSO tokens (`ArkeAuth.SSOGuardian`) cannot be refreshed through this function.

**Symptom:** refreshing an SSO token returns `"invalid token"` even though the token is valid — it was signed by `SSOGuardian` but verified against `Guardian`'s secret.

**What to do:** if you need SSO token refresh, you'll need to implement a parallel path using `SSOGuardian.decode_and_verify/2` and `SSOGuardian.exchange/3`.

---

## `String.to_existing_atom` in Guardian claims

`ArkeAuth.Guardian.resource_from_claims/1` calls `String.to_existing_atom(claims["sub"]["project"])` to convert the project string back to an atom. If the atom doesn't exist yet (e.g. the project hasn't been loaded), this raises `ArgumentError`.

**Symptom:** valid JWT tokens fail authentication with a crash, not a clean `{:error, _}`.

**What to do:** ensure all project atoms are created before any tokens are decoded. Typically this happens at boot via `mix arke.seed_project`, but if a project is created dynamically (via API), its atom must be registered before tokens for that project can be verified.

---

## SSOGuardian stores unused variable

`ArkeAuth.SSOGuardian.resource_from_claims/1` fetches `data = Map.get(user, :data, %{})` but never uses it — the User is returned directly. This is harmless but confusing when reading the source.

---

## OTP bypass is global

The `OTP_BYPASS_CODE` environment variable affects **all** projects, **all** actions, and **all** members. There's no way to bypass OTP for only specific users or test accounts.

**What trips people up:** setting this in a staging environment means real users can also use the bypass code.

**What to do:** only set `OTP_BYPASS_CODE` in test/development environments. For staging, use the `APP_REVIEW_EMAIL` + `APP_REVIEW_CODE` mechanism in `arke_server` instead — that's scoped to specific email addresses.

---

## OTP code is a string, not an integer

`Otp.generate/4` produces a 4-digit code via `Enum.random(1_000..9_999) |> Integer.to_string()`. The code stored in the database is a **string** (e.g. `"4821"`), not an integer.

**What trips people up:** comparing the submitted code as an integer (`1234 == otp.data.code`) always fails because the stored value is `"1234"`.

**What to do:** always compare OTP codes as strings: `to_string(submitted_code) == otp.data.code`.

---

## Permission merge: public takes precedence... sort of

The merge logic in `get_member_permission/3` is:

```elixir
Map.merge(member_public_permission, member_permission, fn _k, v1, v2 ->
  if v1, do: v1, else: v2
end)
```

This means: if the **public** permission for a field is truthy, it wins. If public is falsy (false or nil), the member-specific value is used.

**What trips people up:** you might expect member-specific permissions to always override public, but it's the other way around. Public permissions are a floor — if something is public, no member-specific rule can revoke it.

**What to do:** design your permission links knowing that `member_public` permissions can never be restricted by member-specific permissions. If you need an Arke to be public for reads but restricted for a specific member type, you can't override public `get: true` with member-specific `get: false`.

---

## super_admin bypasses everything, including filter

When the member's `arke_id` is `:super_admin`, the `permission_dict/2` function returns `%{filter: nil, get: true, put: true, post: true, delete: true}` regardless of what permission links exist.

**What trips people up:** if you've set up row-level filtering (via `filter` in permission metadata) for testing with a super_admin account, the filter never applies.

**What to do:** test permission filters with a non-super_admin member type.

---

## subscription_active: false blocks everything

If a member has `subscription_active: false` in their data, the `permission_dict/2` function returns all-false permissions — `%{get: false, put: false, post: false, delete: false}`.

**What trips people up:** this check is in the permission resolution, not in the authentication flow. A member with an inactive subscription can still authenticate and receive tokens — they just can't do anything with them.

**What to do:** if you want to block login entirely for inactive subscriptions, add that check in `Auth.validate_credentials/3` or in the consuming application's login handler.

---

## TemporaryToken default TTL is config, not function default

`TemporaryToken.generate_token/4` reads the default duration from `Application.get_env(:arke_auth, :temporary_token_expiration, 1800)`. The function's default arg for `duration` is `nil`, which triggers the config lookup.

**What trips people up:** changing the function call to `generate_token(project, 0)` passes `0` seconds, not the default. Only `nil` triggers the config lookup.

---

## Member.before_unit_create uses String.to_existing_atom

When `arke_system_user` is a map (inline User creation), `Member.before_unit_create/2` converts map keys via `String.to_existing_atom/1`. If a key in the user data map doesn't correspond to an existing atom, it raises `ArgumentError`.

**What trips people up:** passing custom or misspelled keys (e.g. `%{"pasword" => "secret"}`) causes a crash, not a validation error.

**What to do:** ensure User data maps use only keys that are registered as parameter atoms in the `:user` Arke definition (e.g. `"username"`, `"email"`, `"password"`, `"first_name"`, `"last_name"`).

---

## No rate limiting on any auth operation

Neither `validate_credentials`, `Otp.generate`, nor `refresh_tokens` have built-in rate limiting. A caller can retry credentials indefinitely, generate unlimited OTP codes, or flood the refresh endpoint.

**What to do:** implement rate limiting at the HTTP layer (`arke_server` or a reverse proxy). ArkeAuth provides no protection against brute-force attacks.

---

## ResetPasswordToken requires explicit user_id

`ResetPasswordToken.before_load/2` calls `Map.fetch!(data, :user_id)`. If you create a reset token without providing `user_id`, the error is a `KeyError` crash, not a clean validation error.

**What to do:** always pass `user_id` when creating a reset password token via `QueryManager.create`.
