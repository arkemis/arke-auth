defmodule ArkeAuth.Core.MemberTest do
  use ArkeAuth.RepoCase

  defp member_model, do: ArkeManager.get(:super_admin, :arke_system)

  defp signup(overrides \\ %{}) do
    QueryManager.create(
      :test_schema,
      member_model(),
      arke_system_user:
        Map.merge(
          %{
            "username" => "ada",
            "email" => "ada@arke.test",
            "password" => "secret123",
            "first_name" => "Ada"
          },
          overrides
        )
    )
  end

  defp user_named(username),
    do: QueryManager.get_by(project: :arke_system, arke_id: :user, username: username)

  describe "before_unit_create/2 with a nested arke_system_user" do
    test "creates the user and logs in end to end" do
      {:ok, member} = signup()

      user = user_named("ada")

      assert user.data.email == "ada@arke.test"
      assert user.data.first_name == "Ada"
      refute Map.has_key?(user.data, :password)
      assert {:ok, ^user} = User.check_password(user, "secret123")

      assert {:ok, logged_in, _access, _refresh} =
               Auth.validate_credentials("ada", "secret123", :test_schema)

      assert logged_in.id == member.id
    end

    test "stores arke_system_user as a binary, like the direct path" do
      {:ok, nested} = signup()

      {:ok, direct} =
        QueryManager.create(:test_schema, member_model(), %{
          arke_system_user: to_string(user_named("ada").id)
        })

      assert is_binary(nested.data.arke_system_user)
      assert nested.data.arke_system_user == direct.data.arke_system_user
    end

    # keys go through String.to_existing_atom; the raise is swallowed by arke's
    # hook dispatch and surfaces as this opaque error. What matters here is that
    # no user is left behind.
    test "an unknown user key fails without half-creating the user" do
      assert {:error, "Undefined function"} = signup(%{"not_a_user_parameter" => "x"})
      assert user_named("ada") == nil
    end

    test "a duplicate email is rejected" do
      {:ok, _member} = signup()

      assert {:error, [%{context: "parameter_validation", message: msg}]} =
               signup(%{"username" => "grace"})

      assert msg == "duplicate values are not allowed for: email"
    end
  end

  describe "before_unit_update/2 with a nested arke_system_user" do
    test "updates the linked user" do
      {:ok, member} = signup()

      {:ok, updated} = QueryManager.update(member, arke_system_user: %{"first_name" => "Grace"})

      assert user_named("ada").data.first_name == "Grace"
      assert updated.data.arke_system_user == member.data.arke_system_user
    end
  end

  describe "on_unit_delete/2" do
    test "deletes the member's arke_system user" do
      {:ok, member} = signup()
      assert user_named("ada")

      {:ok, _} = QueryManager.delete(:test_schema, member)

      assert user_named("ada") == nil
      assert QueryManager.get_by(project: :test_schema, id: to_string(member.id)) == nil
    end
  end
end
