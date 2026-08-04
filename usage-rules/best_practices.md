# Best practices

- Do not upgrade `comeonin`/`bcrypt_elixir` independently: the package pins the
  legacy `comeonin ~> 4.0` API (`Comeonin.Bcrypt.hashpwsalt/1`, `checkpw/2`)
  which was removed in comeonin 5.x. Upgrading breaks password verification.
- `ArkeAuth.Utils.Permission` is the only permission API. The dead copies that
  used to live in `ArkeAuth.Core.Member` (`handle_get_permission/2` and
  friends) have been removed.
- Member `arke_id`s and inline `arke_system_user` keys go through
  `String.to_existing_atom` — a typo does not produce a validation error. The
  raise is swallowed by arke's hook dispatch and comes back as
  `{:error, "Undefined function"}`, with nothing written. Validate input keys
  before calling.
- `Member` update hooks call `Atom.to_string(unit.id)` — always work with
  units whose ids are atoms (the normal case when they come from
  `QueryManager`); hand-built units with binary ids crash.
- Deleting a member whose user was already removed crashes in
  `on_unit_delete` (nil user) — and the member row is already gone by then.
  Delete users only through their members.
- Expect all auth errors in the canonical Arke error shape:
  `{:error, [%{context: "auth", message: "..."}]}` with string context.
- The OTP manager GenServer is registered under the name
  `Arke.Boundary.OtpManager` (the `Arke.` namespace, not `ArkeAuth.`) — relevant
  only if you address the process by name.
