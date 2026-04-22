# ArkeAuth — LLM Knowledge Pack

ArkeAuth is the **authentication, authorization, and identity layer** of the Arke ecosystem — an Elixir package that provides user management, JWT token handling (via Guardian), project-scoped member permissions, OTP codes, password reset flows, temporary tokens, and SSO support. It builds on top of the core `arke` package: users and members are Arke Units, permissions are stored as `arke_link` records, and everything flows through `Arke.QueryManager`.

This library handles identity. Sibling packages (`arke` for the schema/CRUD engine, `arke_postgres` for persistence, `arke_server` for HTTP routes) plug around it.

**Current version:** 0.4.4 · **License:** Apache-2.0 · **Source:** <https://github.com/arkemis/arke-auth> · **Hex:** <https://hex.pm/packages/arke_auth>

## Read order

Start with `overview.md`. After that the files are independent — jump to whichever matches the task.

| File | When to read |
|---|---|
| [overview.md](overview.md) | **Always read first.** Mental model: User / Member / Guardian / Permission / OTP / Token, authentication flow, authorization model. |
| [reference.md](reference.md) | Looking up a specific module or function signature. |
| [recipes.md](recipes.md) | Common tasks: login, token refresh, password reset, OTP verification, permission checks, member management. |
| [gotchas.md](gotchas.md) | Something behaves unexpectedly. Sharp edges and non-obvious defaults. |
| [design.md](design.md) | Questions about *why* something is shaped this way — useful when debugging or evaluating changes. |

## What ArkeAuth is not

- Not a standalone auth library. It requires the `arke` core package for schema, CRUD, and persistence.
- Not an HTTP layer. It provides no routes, controllers, or plugs — `arke_server` does that.
- Not an OAuth implementation. OAuth Arke definitions exist (Google, Apple, Facebook, Microsoft) but the actual OAuth flow logic lives in the consuming application or `arke_server`.

## Minimum you need to use it

```elixir
# mix.exs
{:arke_auth, "~> 0.4.4"},
{:arke, "~> 0.6.0"},
{:arke_postgres, "~> x.y.z"}  # or equivalent persistence plug

# config/config.exs
config :arke_auth, ArkeAuth.Guardian,
  issuer: "arke_auth",
  secret_key: "YOUR_SECRET_KEY",
  verify_issuer: true,
  token_ttl: %{"access" => {7, :days}, "refresh" => {30, :days}}
```

Without the Guardian config, all token operations will fail. Without `arke` persistence configured, all user/member CRUD will crash. See [overview.md](overview.md#authentication-flow) for the full flow.
