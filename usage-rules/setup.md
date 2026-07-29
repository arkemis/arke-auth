# Setup

- Add `arke_auth` alongside its required siblings — it cannot work standalone:

  ```elixir
  {:arke, "~> 0.6.0"},
  {:arke_auth, "~> 0.4.4"},
  {:arke_postgres, "~> 0.5.0"}   # or another persistence layer wired into :arke
  ```

- Configure `ArkeAuth.Guardian` — it is mandatory for any token operation:

  ```elixir
  config :arke_auth, ArkeAuth.Guardian,
    issuer: "arke_auth",
    secret_key: System.fetch_env!("GUARDIAN_SECRET"),
    verify_issuer: true,
    token_ttl: %{"access" => {7, :days}, "refresh" => {30, :days}}
  ```

- `ArkeAuth.SSOGuardian` has a completely independent config (own `secret_key`,
  own `token_ttl`). Configure it only if you use SSO flows.
- Optional config keys:

  ```elixir
  config :arke_auth, ArkeAuth.Otp, ttl: {5, :minutes}      # units: :seconds | :minutes | :days ONLY
  config :arke_auth, :temporary_token_expiration, 1800     # seconds
  config :arke_auth, :reset_password_token_ttl, weeks: 2   # Timex.shift options
  ```

- Seed every project after creating it — this is what installs `super_admin`,
  `member_public`, `temporary_token` and the `arke_auth_member` group:

  ```bash
  mix arke.seed_project --project my_project
  ```

- Registry discovery only scans declared deps whose name contains `"arke"`:
  `arke_auth` must be a direct dependency of the consuming app or its Arkes are
  never seeded.
- The `subscription_active` and `inactive` member fields drive behavior
  (permission lockout, login rejection) but are NOT defined by any shipped
  registry — define them as parameters on your member Arkes if you want to use
  them; absent, the related checks simply never fire.
