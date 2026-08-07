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
- Member + User creation is atomic (arke ≥ 0.9.0): the inline User create
  joins the member's transaction, so a failing member insert rolls the User
  back — no orphaned `:arke_system` user occupying the username. On older
  versions the orphan stays.
- Passwords are hashed (bcrypt) in the `:user` Arke's `before_load` hook, which
  fires only on `:create`. Never write a user record through a path that
  bypasses `Arke.QueryManager.create/3`.
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

- `Auth.update/2` silently strips `:password` from the update args and still
  returns `{:ok, ...}` — do not use it to change passwords.
- **Deleting a Member deletes its User** (`on_unit_delete` cascades to
  `:arke_system`), orphaning that User's Members in other projects. There is no
  built-in guard — check for sibling members before deleting.
