# Users and Members

- A **User** is a global credential record: an Arke Unit with `arke_id: :user`
  living in the `:arke_system` project. A **Member** is a project-scoped Unit
  belonging to the `arke_auth_member` Group, pointing at its User via the
  `arke_system_user` parameter. One User can have many Members across projects.
- A member's **role IS its `arke_id`** (`:super_admin`, `:admin`, or any custom
  Arke you register into the `arke_auth_member` group). There is no separate
  role field.
- Login is two-step: credentials are verified against the User in
  `:arke_system`, then the Member is looked up in the requested project. Never
  look for a password on the member.
- Create a Member and its User in one call via the inline `arke_system_user`
  map — keys must be strings that already exist as atoms (registered parameters
  of the `:user` Arke; unknown keys raise `ArgumentError`):

  ```elixir
  arke = Arke.Boundary.ArkeManager.get(:admin, :my_project)
  {:ok, member} = Arke.QueryManager.create(:my_project, arke,
    arke_system_user: %{
      "username" => "ada@example.com", "email" => "ada@example.com",
      "password" => "secret123", "first_name" => "Ada", "last_name" => "Lovelace"
    })
  ```

- To link an existing User instead, pass its id as a binary:
  `arke_system_user: "user_id"`.
- Updating a Member with an inline `arke_system_user` map writes to the
  **global** User, so it is restricted to an allow-list of profile fields
  (default `[:first_name, :last_name, :phone_number]`, set with
  `config :arke_auth, ArkeAuth.Core.Member, user_update_fields: [...]`).
  `password` and `password_hash` can never be listed. Other fields fail the
  update with `"arke_system_user.<field> cannot be updated"` unless they are
  echoed back unchanged. A Member cannot be re-pointed at another User
  (`"arke_system_user cannot be changed"`).
- Member + User creation is atomic (arke ≥ 0.9.0): the inline User create
  joins the member's transaction, so a failing member insert rolls the User
  back — no orphaned `:arke_system` user occupying the username. On older
  versions the orphan stays.
- That atomicity requires `transaction: &ArkePostgres.transaction/2` in
  `config :arke, persistence:`. Without it arke substitutes a pass-through and
  the orphan comes back, silently.
- Passwords are hashed (bcrypt) on `:create` (`before_load`) and on `:update`
  (a `before_write` hook): pass the plain `password`, never a hash. An update
  whose `password_hash` differs from the stored one is rejected with
  `"password_hash cannot be set directly"`.
- Change passwords ONLY via `Auth.change_password/3`, and resolve the User
  first — passing the member is wrong:

  ```elixir
  # WRONG — member has no password
  Auth.change_password(member, old_pwd, new_pwd)

  # CORRECT
  user = Arke.QueryManager.get_by(project: :arke_system, arke_id: :user,
    id: member.data.arke_system_user)
  {:ok, _} = ArkeAuth.Core.Auth.change_password(user, old_pwd, new_pwd)
  ```

- `Auth.update/2` silently strips `:password` and `:password_hash` from the
  update args and still returns `{:ok, ...}` — do not use it to change
  passwords.
- Deleting a Member unlinks it from its User. The User is deleted only when no
  Member in any project (the `:arke_system` project, the deleted member's
  project and every `:arke_project`) still references it.
