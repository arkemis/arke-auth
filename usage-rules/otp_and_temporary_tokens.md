# OTP and temporary tokens

## OTP codes

- Generate with `ArkeAuth.Core.Otp.generate(project, member_id, action)` and
  look up with `ArkeAuth.Boundary.OtpManager.get_code(project, member, action)`.
- **Omit the 4th argument of `Otp.generate/4`** to get the configured TTL.
  Passing `nil` explicitly does NOT read the config — it falls back to a
  hardcoded 300 seconds.
- OTP codes are 6-digit **strings** (`"042917"`) drawn from a CSPRNG. Set
  `config :arke_auth, ArkeAuth.Otp, digits: n` for longer codes; values below 6
  are raised to 6.
- Verify with `ArkeAuth.Boundary.OtpManager.verify_code/4`, never by comparing
  `otp.data.code` yourself. It compares in constant time, consumes the code on
  success, and burns it after `max_attempts` (default 5) wrong guesses or on
  expiry:

  ```elixir
  case ArkeAuth.Boundary.OtpManager.verify_code(:my_project, member, "signin", submitted) do
    {:ok, _otp} -> :ok
    {:error, [%{message: "otp expired"}]} -> :gone
    {:error, [%{message: "too many attempts"}]} -> :locked
    {:error, [%{message: "invalid otp"}]} -> :unauthorized
  end
  ```

  For signup codes generated against a username, pass the username in place
  of the member.
- Attempt counters are node-local (ETS) and reset on restart; keep per-source
  rate limiting at the HTTP layer as well.
- `config :arke_auth, ArkeAuth.Otp, ttl: {n, unit}, max_attempts: n` — `ttl` accepts only `:seconds`,
  `:minutes`, `:days` — `:hours`/`:weeks` crash with `FunctionClauseError`.
- `OTP_BYPASS_CODE`, when set, replaces the code of every member in every
  project for every action (`reset_password` included). `get_code/3` then
  returns a map with `bypass: true`, and the real code is ignored. It clears
  the second factor deployment-wide: set it only in local development. Wrong guesses against it are still throttled
  by `verify_code/4` (`max_attempts` per member and action every 5 minutes).
- The `:otp` Arke is always resolved from `:arke_system` — it must exist there
  even when generating OTPs for other projects.

## Temporary tokens

- `ArkeAuth.Core.TemporaryToken.generate_token(project, duration, is_reusable, opts)`
  and `generate_auth_token/4` for member-bound tokens.
- The token's **id is its secret**: 32 random bytes, hex encoded (64 chars).
  An `:id` passed in `opts` is ignored. Treat the id like a password: send it
  in a request body or header rather than a query string, keep tokens
  single-use (`is_reusable: false`, the default) and short-lived.
- The default TTL applies only when `duration` is `nil` — `0` means zero
  seconds, not "use the default".
- Duration maps support `%{days: d}` OR `%{minutes: m}` but NOT both:
  `%{days: 1, minutes: 30}` silently ignores `minutes` (clause-order bug).

## Reset-password tokens

- Create via `Arke.QueryManager.create/3` on the `:reset_password_token` Arke;
  `user_id` is mandatory and its absence raises `KeyError` (not a validation
  error). `token` and `expiration` are auto-generated in `before_load`.
