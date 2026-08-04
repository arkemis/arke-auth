defmodule ArkeAuth.Utils.PermissionTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Utils.Permission

  @none %{filter: nil, get: false, put: false, post: false, delete: false, child_only: false}

  # a permission is an arke_link row with the flags in its metadata; created
  # directly because roles are arke ids, and arkes are not persisted units here
  defp permission_link(parent_id, metadata, project \\ :test_schema) do
    {:ok, link} =
      QueryManager.create(project, ArkeManager.get(:arke_link, :arke_system),
        parent_id: parent_id,
        child_id: "user",
        type: "permission",
        metadata: metadata
      )

    link
  end

  defp member(overrides \\ %{}), do: Map.merge(%{arke_id: :admin, data: %{}}, overrides)

  describe "get_public_permission/2" do
    test "returns every flag false when nothing is granted" do
      assert Permission.get_public_permission("user", :test_schema) == {:ok, @none}
    end

    test "returns the flags of the member_public link" do
      permission_link("member_public", %{"get" => true, "filter" => "eq(id,1)"})

      assert {:ok, permission} = Permission.get_public_permission("user", :test_schema)
      assert permission == %{@none | get: true, filter: "eq(id,1)"}
    end

    test "ignores role-scoped links" do
      permission_link("admin", %{"get" => true, "post" => true})

      assert Permission.get_public_permission("user", :test_schema) == {:ok, @none}
    end

    # the unit form takes the project from the arke's own metadata, not from the
    # project the caller asked the manager for
    test "accepts an arke unit" do
      arke = ArkeManager.get(:user, :test_schema)
      permission_link("member_public", %{"get" => true}, arke.metadata.project)

      assert {:ok, %{get: true}} = Permission.get_public_permission(arke)
    end
  end

  describe "get_member_permission/3" do
    test "returns every flag false when nothing is granted" do
      assert Permission.get_member_permission(member(), "user", :test_schema) == {:ok, @none}
    end

    test "returns the flags of the member's role" do
      permission_link("admin", %{"get" => true, "post" => true, "child_only" => true})

      assert Permission.get_member_permission(member(), "user", :test_schema) ==
               {:ok, %{@none | get: true, post: true, child_only: true}}
    end

    test "public permissions are a floor the role cannot revoke" do
      permission_link("member_public", %{"get" => true})
      permission_link("admin", %{"get" => false, "post" => true})

      assert Permission.get_member_permission(member(), "user", :test_schema) ==
               {:ok, %{@none | get: true, post: true}}
    end

    test "a role of a different name gets nothing" do
      permission_link("admin", %{"get" => true})

      assert Permission.get_member_permission(member(%{arke_id: :editor}), "user", :test_schema) ==
               {:ok, @none}
    end

    test "super_admin bypasses everything, including filter" do
      permission_link("member_public", %{"get" => false, "filter" => "eq(id,1)"})

      assert Permission.get_member_permission(
               member(%{arke_id: :super_admin}),
               "user",
               :test_schema
             ) == {:ok, %{filter: nil, get: true, put: true, post: true, delete: true}}
    end

    test "subscription_active: false zeroes every flag" do
      permission_link("admin", %{"get" => true, "post" => true})

      assert Permission.get_member_permission(
               member(%{data: %{subscription_active: false}}),
               "user",
               :test_schema
             ) == {:ok, %{filter: nil, get: false, put: false, post: false, delete: false}}
    end

    test "accepts an arke unit" do
      arke = ArkeManager.get(:user, :test_schema)
      permission_link("admin", %{"get" => true}, arke.metadata.project)

      assert {:ok, %{get: true}} = Permission.get_member_permission(member(), arke)
    end
  end

  describe "get_member_permission/3 while impersonating" do
    defp put_allowed_methods(methods) do
      config = Application.get_env(:arke_auth, ArkeAuth.Guardian)
      on_exit(fn -> Application.put_env(:arke_auth, ArkeAuth.Guardian, config) end)

      Application.put_env(
        :arke_auth,
        ArkeAuth.Guardian,
        Keyword.put(config, :allowed_methods, methods)
      )
    end

    test "the granted flags are intersected with allowed_methods" do
      put_allowed_methods(%{get: true, post: false, put: false, delete: false})
      permission_link("admin", %{"get" => true, "post" => true, "put" => true})

      assert Permission.get_member_permission(
               member(%{impersonate: true}),
               "user",
               :test_schema
             ) == {:ok, %{@none | get: true}}
    end

    # documented all-or-nothing config: enable_impersonate without
    # allowed_methods is Map.merge(flags, nil)
    test "crashes when allowed_methods is not configured" do
      assert_raise BadMapError, fn ->
        Permission.get_member_permission(member(%{impersonate: true}), "user", :test_schema)
      end
    end
  end
end
