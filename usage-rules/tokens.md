# Tokens

- Sign in with `ArkeAuth.Core.Auth.validate_credentials/3`:

  ```elixir
  case ArkeAuth.Core.Auth.validate_credentials(username, password, :my_project) do
    {:ok, member, access_token, refresh_token} -> ...
    {:error, [%{context: "auth", message: "unauthorized"}]} -> ...
  end
  ```

- The `"unauthorized"` error deliberately collapses unknown-username,
  bad-password, not-a-member and inactive-member into one message — do not try
  to distinguish them from the error.
- Error `context` values are **strings** at runtime (`"auth"`), never atoms —
  match on `%{context: "auth"}`.
- Refresh with `Auth.refresh_tokens(member, refresh_token)` →
  `{:ok, new_access, new_refresh}`. Refresh is hardcoded to `ArkeAuth.Guardian`;
  SSO tokens cannot be refreshed through it (they fail with `"invalid token"`).
- Never call `ArkeAuth.Guardian.encode_and_sign/2` with a raw member `%Unit{}`:
  `subject_for_token/2` merges the **whole** `member.data` into the JWT payload.
  Always pre-shape with `Auth.format_member(member)` (email, first/last name,
  subscription_active only) unless leaking every member field is acceptable:

  ```elixir
  # WRONG — every member field ends up in the token
  ArkeAuth.Guardian.encode_and_sign(member, %{})

  # CORRECT
  ArkeAuth.Guardian.encode_and_sign(ArkeAuth.Core.Auth.format_member(member), %{})
  ```

- In a Plug context, read the current member with
  `ArkeAuth.Guardian.get_member(conn)`; pass `impersonate: true` to get the
  impersonated target instead of the impersonating admin.
- `Guardian.resource_from_claims/1` calls `String.to_existing_atom` on the
  project claim — if the project atom is not loaded yet it raises
  `ArgumentError` instead of returning `{:error, _}`.
- Impersonation is opt-in and its config is all-or-nothing: with
  `enable_impersonate: true` you MUST also set `allowed_methods`, or every
  impersonated permission check crashes with `BadMapError`:

  ```elixir
  config :arke_auth, ArkeAuth.Guardian,
    enable_impersonate: true,
    allowed_methods: %{get: true, post: false, put: false, delete: false}
  ```

- There is no rate limiting on `validate_credentials/3`, `refresh_tokens/2` or
  OTP generation — add throttling at the HTTP layer.
