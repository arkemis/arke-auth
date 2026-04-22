# Design — Why It's Shaped This Way

Rationale behind the load-bearing decisions in arke_auth. Useful for:
- **Devs** making sense of unexpected behavior ("it's this way because...")

These are architectural commitments, not implementation details. Changing them would cascade through `arke_server` and any consuming application.

---

## Why Users and Members are separate

**The choice:** a **User** lives in `:arke_system` (global), while a **Member** lives in a project (tenant-scoped) and references a User via `arke_system_user`. Logging in verifies the User, then looks up the Member in the target project.

**What this buys:**
- One person, many tenants. A single set of credentials (username/password) grants access to multiple projects — each project has its own Member with its own role (`arke_id`) and permissions.
- Password management is centralized. Changing a password in `:arke_system` takes effect across all projects instantly.
- The User is a clean identity record; project-specific concerns (roles, subscription status, custom fields) live on the Member.

**The cost:**
- Two-step lookup on login: first User (by username in `:arke_system`), then Member (by `arke_system_user` in the project). If either is missing, the error is generic ("unauthorized") — no distinction between "bad password" and "not a member of this project."
- Member deletion cascades to User deletion (`on_unit_delete`). If a User belongs to multiple projects, deleting one project's Member wipes the shared User. This is a known hazard — see [gotchas.md](gotchas.md#member-delete-cascades-to-user).

**Compared to a single-entity approach:** a single "member" per project would be simpler but would require duplicating credentials per project, complicating password resets and cross-project SSO.

**When to revisit:** if the system needs Members without shared Users (e.g. anonymous project members, API keys), the cascade delete and the mandatory `arke_system_user` link would need an opt-out path.

---

## Why Member is a Group, not an Arke

**The choice:** `ArkeAuth.Core.Member` uses `use Arke.System.Group` with `group id: "arke_auth_member"`. This means the actual Arkes (`:super_admin`, `:admin`, `:editor`, etc.) are members of the Group, and every Unit of any of those Arkes is a "Member" in the auth sense.

**What this buys:**
- Role-as-Arke. A member's role is its `arke_id` — the Arke it's an instance of. This means roles can have different custom fields (a `:super_admin` might have `admin_notes`, an `:editor` might have `department`).
- Group hooks fire for all member types. `before_unit_create`, `on_unit_delete`, etc. apply uniformly — the User cascade works regardless of which member Arke is used.
- The permission system naturally keys on `member.arke_id` — no extra "role" field needed.

**The cost:**
- Adding a new role means creating a new Arke and registering it in the `arke_auth_member` Group. This is a schema operation, not just a data insert.
- Querying "all members" requires `group_id: "arke_auth_member"`, not a simple `arke_id:` filter. Code that forgets this misses members.
- The Group-level hooks in `ArkeAuth.Core.Member` are the only place cascade logic lives — if a member Arke overrides `before_unit_create` in its own module, the Group hook still fires (Group hooks run after Arke hooks), but ordering can be subtle.

**When to revisit:** if roles need to be fully dynamic (created at runtime, no code change), the current model works but requires seeding new Arke definitions. A simpler "role" string field on a single `:member` Arke would lose the per-role schema flexibility but be operationally simpler.

---

## Why Guardian with two modules

**The choice:** two separate Guardian implementations — `ArkeAuth.Guardian` for project-scoped member auth, `ArkeAuth.SSOGuardian` for system-level user auth.

**What this buys:**
- Clear separation of concerns. Member tokens carry project context; SSO tokens don't. The `resource_from_claims` implementations look up fundamentally different things (member by group in a project vs. user by ID in `:arke_system`).
- `arke_server` can wire different pipelines for member auth vs. SSO auth, each using the appropriate Guardian module.
- Token payloads differ: member tokens include `project`, `email`, `subscription_active`; SSO tokens include the full user data (minus password).

**The cost:**
- Two Guardian configs. Both need `secret_key`, `issuer`, `token_ttl` — forgetting one causes cryptic errors.
- `Auth.create_tokens/2` dispatches on a `"sso"` string parameter, which is an implicit contract with the caller.
- Refresh token exchange (`Auth.refresh_tokens/2`) is hardcoded to `ArkeAuth.Guardian` — SSO tokens can't be refreshed through the same path.

**When to revisit:** if SSO needs refresh tokens or if a third token type emerges (e.g. API keys, service tokens), the string-dispatch in `create_tokens/2` will become a code smell. A behaviour or protocol for token strategies would be cleaner.

---

## Why permissions are link-based

**The choice:** permissions are `arke_link` Units with `type: "permission"`, using the existing link infrastructure rather than a dedicated permission table.

**What this buys:**
- No new storage model. Permissions use the same `arke_link` table and the same `QueryManager` CRUD as every other relationship in the system.
- The link metadata field is a JSONB dict — permission flags (`get`, `put`, `post`, `delete`, `filter`, `child_only`) are just metadata keys. Adding a new flag requires no migration.
- Permission queries are standard Arke queries: `where(parent_id__in: [...], child_id: arke_id, type: "permission")`.

**The cost:**
- No FK constraints. A permission link can reference a non-existent Arke or member type — nothing in the DB prevents dangling permissions.
- Permission resolution is a per-request DB query (two-way: public + member-specific). There's no caching layer — every `get_member_permission` call hits the DB via `QueryManager`.
- The merge logic (public vs. member, super_admin bypass, subscription check) is in application code, not declarative — it's easy to miss an edge case.

**Compared to RBAC tables:** a dedicated `permissions` table with FK constraints and indexes would be more performant and safer. The link-based approach trades that for consistency with the rest of the Arke model.

**When to revisit:** if permission checks become a performance bottleneck, adding an ETS cache (keyed by `{member_arke_id, target_arke_id, project}`) would be a natural addition. The data model wouldn't change — just the read path.

---

## Why OTP codes are database-persisted

**The choice:** OTP codes are Arke Units (arke_id: `:otp`) stored via `QueryManager.create`. Each generation deletes the previous code for the same action+member.

**What this buys:**
- OTP codes survive node restarts — they're in the DB, not in ETS or GenServer state.
- The standard Arke CRUD pipeline handles validation, persistence, and deletion.
- Multi-node: any node can verify an OTP code since it's in the shared DB.

**The cost:**
- DB write on every OTP generation, DB read on every verification. For high-volume OTP flows, this is heavier than an in-memory store.
- No rate limiting built in. An attacker can trigger unlimited OTP generations (and DB writes) without throttling.
- The `OTP_BYPASS_CODE` env var is a global backdoor — it bypasses all OTP checks, not just for specific test users.

**When to revisit:** if OTP volume becomes a concern, moving to Redis or ETS with TTL would reduce DB load. The `OtpManager` (ETS-backed) already exists but is currently used only for bypass logic, not as the primary store.

---

## Why password hashing is in the before_load hook

**The choice:** `ArkeAuth.Core.User.before_load/2` intercepts the `:create` persistence function, hashes the `password` field, stores `password_hash`, and deletes `password` from the data — all before the Unit struct is built.

**What this buys:**
- The plaintext password never exists on the Unit struct. By the time `%Unit{}` is constructed, only `password_hash` is present.
- Works with Arke's standard pipeline — no special password-handling path needed outside of `before_load`.

**The cost:**
- The hook only fires on `:create`. Password changes go through `User.update_password/2`, which calls `QueryManager.update` with a pre-hashed value — a separate path that must also use bcrypt correctly.
- If someone creates a User via `QueryManager.create` without going through the hook (e.g. raw persistence), the password won't be hashed.
- The hook checks `Map.get(data, :arke_id)` to detect "is this coming from DB?" — a non-obvious convention.

---

## Decisions explicitly left flexible

- **Token TTL** — fully configurable per deployment via Guardian config (`token_ttl`).
- **OTP TTL** — configurable via `ArkeAuth.Otp` config.
- **Reset password token TTL** — configurable via `:reset_password_token_ttl`.
- **Temporary token duration** — configurable per generation call or globally via `:temporary_token_expiration`.
- **Impersonation** — disabled by default; opt-in via `enable_impersonate: true` in Guardian config.

---

## Decisions that are non-negotiable (by current design)

- **User/Member split.** Removing this would mean redesigning the login flow, the Member Group hooks, and the multi-tenant scoping model.
- **Guardian as the JWT engine.** The entire token lifecycle (`encode_and_sign`, `exchange`, `resource_from_claims`, Plug integration) depends on Guardian's API. Swapping it would touch every auth surface.
- **Permissions as arke_links.** The permission resolution code, the `arke_server` Permission plug, and the admin tooling all assume link-based permissions. Moving to a dedicated table would cascade through the whole stack.

If a roadmap conversation touches any of these three, treat it as foundational work, not incremental.
