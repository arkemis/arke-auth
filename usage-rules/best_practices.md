# Best practices

- Do not upgrade `comeonin`/`bcrypt_elixir` independently: the package pins the
  legacy `comeonin ~> 4.0` API (`Comeonin.Bcrypt.hashpwsalt/1`, `checkpw/2`)
  which was removed in comeonin 5.x. Upgrading breaks password verification.
- Do not call or copy the private permission helpers inside
  `ArkeAuth.Core.Member` (`handle_get_permission/2` and friends) — they are
  dead, buggy leftovers. `ArkeAuth.Utils.Permission` is the only permission
  API.
- Do not treat the test suite as executable documentation — parts of it
  reference helpers that no longer exist.
- Member `arke_id`s and inline `arke_system_user` keys go through
  `String.to_existing_atom` — typos raise `ArgumentError` rather than
  returning a validation error. Validate input keys before calling.
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
