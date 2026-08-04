defmodule AuthTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Guardian

  def create_user(_context) do
    user_model = ArkeManager.get(:user, :arke_system)
    {:ok, user} = QueryManager.create(:arke_system, user_model, get_user_params())

    member_model = ArkeManager.get(:super_admin, :arke_system)

    {:ok, _member} =
      QueryManager.create(:test_schema, member_model, %{arke_system_user: to_string(user.id)})

    :ok
  end

  def get_user(_context) do
    user = QueryManager.get_by(project: :arke_system, arke_id: :user, username: "test")

    %{
      user: user,
      # the arke_system_user discriminator keeps this deterministic once another
      # test adds a second member to :test_schema — get_by takes List.first of an
      # unordered select
      member:
        QueryManager.get_by(
          project: :test_schema,
          group_id: "arke_auth_member",
          arke_system_user: to_string(user.id)
        )
    }
  end

  defp get_user_params,
    do: %{username: "test", password: "password", email: "test@arke.test"}

  describe "ArkeAuth" do
    setup [:create_user, :get_user]

    test "update", %{user: user} = _context do
      new_data = %{first_name: "Updated"}
      {:ok, edited_user} = Auth.update(user, new_data)
      assert user.data.first_name != edited_user.data.first_name
    end

    test "update ignores :password", %{user: user} = _context do
      {:ok, edited_user} = Auth.update(user, %{first_name: "Updated", password: "new_password"})

      assert edited_user.data.password_hash == user.data.password_hash
      assert User.check_password(edited_user, "password") == {:ok, edited_user}
    end

    test "validate_credentials", %{member: member} = _context do
      {:ok, updated_user, _access_token, _refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      assert updated_user.id == member.id
    end

    test "validate_credentials (error)" do
      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("wrong_username", "password", :test_schema)

      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("test", "wrong_password", :test_schema)
    end

    test "validate_credentials rejects a project the user is not a member of" do
      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("test", "password", :arke_system)
    end

    test "validate_credentials rejects an inactive member", %{member: member} = _context do
      {:ok, _inactive} = QueryManager.update(member, inactive: true)

      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("test", "password", :test_schema)
    end

    test "the access token carries no password_hash" do
      {:ok, _member, access_token, _refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:ok, claims} = Guardian.decode_and_verify(access_token)

      assert Enum.sort(Map.keys(claims["sub"])) == [
               "email",
               "first_name",
               "id",
               "last_name",
               "project",
               "subscription_active"
             ]
    end

    test "format_member exposes only the token-safe fields", %{member: member} = _context do
      assert Enum.sort(Map.keys(Auth.format_member(member).data)) ==
               [:email, :first_name, :last_name, :subscription_active]
    end

    test "refresh_tokens" do
      {:ok, %Arke.Core.Unit{} = user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:ok, new_access_token, new_refresh_token} = Auth.refresh_tokens(user, refresh_token)
      assert new_access_token != access_token and new_refresh_token != refresh_token
    end

    test "refresh_tokens (error)" do
      {:ok, user, access_token, _refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:error, [%{context: _c, message: msg}]} = Auth.refresh_tokens(user, access_token)
      assert msg == "invalid token"
    end

    test "change_password", %{user: user} = _context do
      Auth.change_password(user, "password", "new_password")

      {:ok, %Arke.Core.Unit{}, _access_token, _refresh_token} =
        Auth.validate_credentials("test", "new_password", :test_schema)

      {:error, [%{context: _c, message: msg}]} =
        Auth.validate_credentials("test", "wrong_password", :test_schema)

      assert msg == "unauthorized"
    end

    test "change_password (error)", %{user: user} = _context do
      assert {:error, [%{context: "auth", message: "invalid attribute format"}]} ==
               Auth.change_password(user, "password", 1234)
    end

    test "create_tokens/2 signs with SSOGuardian for \"sso\"", %{user: user} = _context do
      {:ok, _resource, access_token, refresh_token} = Auth.create_tokens(user, "sso")

      assert {:ok, _claims} = ArkeAuth.SSOGuardian.decode_and_verify(access_token)

      assert {:ok, _claims} =
               ArkeAuth.SSOGuardian.decode_and_verify(refresh_token, %{"typ" => "refresh"})
    end
  end

  # `username` is not unique (`lib/registry/system/parameter.json`) while `email`
  # is, and `Auth.get_by_username/2` takes `List.first` of the matches. Two users
  # can therefore share a username and only one of them can ever log in; which
  # one wins is an ETS/Postgres ordering detail (`LIMIT 1` with no `ORDER BY`),
  # so this asserts the shape of the outcome, not the winner. Accepted as
  # designed: email is the unique identity.
  describe "duplicate username" do
    setup do
      user_model = ArkeManager.get(:user, :arke_system)
      member_model = ArkeManager.get(:super_admin, :arke_system)

      for {email, password} <- [
            {"first@arke.test", "password_one"},
            {"second@arke.test", "password_two"}
          ] do
        {:ok, user} =
          QueryManager.create(:arke_system, user_model, %{
            username: "shared",
            password: password,
            email: email
          })

        {:ok, _member} =
          QueryManager.create(:test_schema, member_model, %{arke_system_user: to_string(user.id)})
      end

      :ok
    end

    test "only one of the two passwords can ever authenticate" do
      results =
        Enum.map(["password_one", "password_two"], fn password ->
          Auth.validate_credentials("shared", password, :test_schema)
        end)

      assert Enum.count(results, &match?({:ok, _member, _access, _refresh}, &1)) == 1
    end
  end
end
