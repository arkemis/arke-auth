# OTP and temporary tokens

## OTP codes

- Generate with `ArkeAuth.Core.Otp.generate(project, member_id, action)` and
  look up with `ArkeAuth.Boundary.OtpManager.get_code(project, member, action)`.
- **Omit the 4th argument of `Otp.generate/4`** to get the configured TTL.
  Passing `nil` explicitly does NOT read the config — it falls back to a
  hardcoded 300 seconds.
- OTP codes are 4-digit **strings** (`"1042"`). Compare with strings, never
  integers:

  ```elixir
  # WRONG
  otp_unit.data.code == 1042

  # CORRECT
  otp_unit.data.code == to_string(submitted_code)
  ```

- Verify expiry yourself and delete the code after use:

  ```elixir
  case ArkeAuth.Boundary.OtpManager.get_code(:my_project, member, "signin") do
    nil -> :not_found
    otp ->
      with true <- otp.data.code == to_string(submitted),
           :gt  <- NaiveDateTime.compare(otp.data.expiry_datetime, NaiveDateTime.utc_now()) do
        ArkeAuth.Boundary.OtpManager.delete_otp(otp)
        :ok
      end
  end
  ```

- `config :arke_auth, ArkeAuth.Otp, ttl: {n, unit}` accepts only `:seconds`,
  `:minutes`, `:days` — `:hours`/`:weeks` crash with `FunctionClauseError`.
- `OTP_BYPASS_CODE` is a GLOBAL bypass (all projects, all actions, all
  members). Never set it outside test/dev environments.
- The `:otp` Arke is always resolved from `:arke_system` — it must exist there
  even when generating OTPs for other projects.

## Temporary tokens

- `ArkeAuth.Core.TemporaryToken.generate_token(project, duration, is_reusable, opts)`
  and `generate_auth_token/4` for member-bound tokens.
- The default TTL applies only when `duration` is `nil` — `0` means zero
  seconds, not "use the default".
- Duration maps support `%{days: d}` OR `%{minutes: m}` but NOT both:
  `%{days: 1, minutes: 30}` silently ignores `minutes` (clause-order bug).

## Reset-password tokens

- Create via `Arke.QueryManager.create/3` on the `:reset_password_token` Arke;
  `user_id` is mandatory and its absence raises `KeyError` (not a validation
  error). `token` and `expiration` are auto-generated in `before_load`.
