# Rules for working with ArkeAuth

## Understanding ArkeAuth

ArkeAuth is the identity and authorization layer of the Arke framework. It defines
no storage and no HTTP surface of its own: Users, Members, permissions, OTP codes
and tokens are all ordinary Arke Units and Links, persisted by the configured
persistence layer (usually `arke_postgres`) and exposed over HTTP by `arke_server`.
On top of the Arke data model it layers bcrypt password hashing, two independent
Guardian JWT modules (`ArkeAuth.Guardian` for project-scoped member tokens,
`ArkeAuth.SSOGuardian` for system-wide SSO tokens), a link-based permission model,
OTP codes, temporary tokens and reset-password tokens.

Read the topic rules in `usage-rules/` before using a feature. Do not assume the
API follows common Elixir auth-library conventions — most operations go through
`Arke.QueryManager` and Arke hooks, not through dedicated auth functions.
