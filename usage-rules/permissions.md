# Permissions

- Permissions are ordinary `arke_link` rows with `type: "permission"`:
  `parent_id` is `"member_public"` or a member role (`arke_id`), `child_id` is
  the target Arke, and the flags live in the link `metadata`
  (`get/post/put/delete/filter/child_only`).
- Grant permissions with `Arke.LinkManager.add_node/5`:

  ```elixir
  # role-scoped
  Arke.LinkManager.add_node(:my_project, "admin", "person", "permission",
    %{"get" => true, "post" => true, "put" => true, "delete" => true,
      "filter" => nil, "child_only" => false})

  # public (unauthenticated / all members)
  Arke.LinkManager.add_node(:my_project, "member_public", "article", "permission",
    %{"get" => true, "post" => false, "put" => false, "delete" => false})
  ```

- Check permissions with `ArkeAuth.Utils.Permission.get_public_permission/2` or
  `get_member_permission/3`. Both **always** return `{:ok, flags}` — when no
  permission link exists the flags are simply all `false`. Never pattern-match
  on an error tuple to detect "no permission"; inspect the flags:

  ```elixir
  # WRONG — this clause never matches
  {:error, nil} = Permission.get_member_permission(member, "person", :p)

  # CORRECT
  {:ok, perm} = ArkeAuth.Utils.Permission.get_member_permission(member, "person", :p)
  if perm.get, do: ..., else: :forbidden
  ```

- **Public permissions are a floor, not a default.** Public and member flags
  are merged with public winning on truthy values — a flag granted to
  `member_public` can never be revoked by a member-specific link. Grant
  publicly only what genuinely everyone may do.
- `:super_admin` bypasses everything, including row-level `filter` — never test
  permission filters with a super_admin member.
- The `filter` flag holds an Arke filter string, e.g.
  `"eq(owner_id,{{arke_member}})"`. The `{{arke_member}}` placeholder is
  substituted by `arke_server`'s Permission plug, NOT by arke_auth — if you
  evaluate filters yourself you must substitute it yourself.
- `subscription_active: false` on a member zeroes all permission flags but does
  NOT block login — the member still receives valid tokens.
- `child_only: true` restricts results to units linked (up to depth 10) to the
  member unit.
