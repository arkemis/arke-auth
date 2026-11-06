defmodule AuthTest do
  use ArkeAuth.RepoCase

  def create_user(_context) do
    user_model = ArkeManager.get(:user, :arke_system)
    {:ok, user} = QueryManager.create(:arke_system, user_model, get_user_params())

    member_model = ArkeManager.get(:super_admin, :arke_system)

    {:ok, _member} =
      QueryManager.create(:test_schema, member_model, %{arke_system_user: to_string(user.id)})

    :ok
  end

  def get_user(_context) do
    %{
      user: QueryManager.get_by(project: :arke_system, arke_id: :user, username: "test"),
      member: QueryManager.get_by(project: :test_schema, group_id: "arke_auth_member")
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

    test "validate_credentials", %{member: member} = _context do
      {:ok, updated_user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      assert updated_user.id == member.id
    end

    test "validate_credentials (error)" do
      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("wrong_username", "password", :test_schema)

      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("test", "wrong_password", :test_schema)
    end

    test "refresh_tokens" do
      {:ok, %Arke.Core.Unit{} = user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:ok, new_access_token, new_refresh_token} = Auth.refresh_tokens(user, refresh_token)
      assert new_access_token != access_token and new_refresh_token != refresh_token
    end

    test "refresh_tokens (error)" do
      {:ok, user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:error, [%{context: _c, message: msg}]} = Auth.refresh_tokens(user, access_token)
      assert assert msg == "invalid token"
    end

    test "a refresh token does not resolve a resource (ARKE-AUTH-04)" do
      {:ok, member, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      assert {:ok, resource, _claims} = ArkeAuth.Guardian.resource_from_token(access_token)
      assert resource.id == member.id

      assert {:error, :invalid_token_type} =
               ArkeAuth.Guardian.resource_from_token(refresh_token)
    end

    test "refresh_tokens resolves the member from the refresh token alone" do
      {:ok, member, _access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:ok, new_access_token, new_refresh_token} = Auth.refresh_tokens(nil, refresh_token)

      assert {:ok, resource, %{"typ" => "access"}} =
               ArkeAuth.Guardian.resource_from_token(new_access_token)

      assert resource.id == member.id

      assert {:ok, %{"typ" => "refresh"}} =
               ArkeAuth.Guardian.decode_and_verify(new_refresh_token)
    end

    test "refresh_tokens ignores the caller's member", %{user: user} do
      {:ok, member, _access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      other = %{member | id: :someone_else}
      {:ok, _access, new_refresh_token} = Auth.refresh_tokens(other, refresh_token)

      {:ok, %{"sub" => %{"id" => id}}} = ArkeAuth.Guardian.decode_and_verify(new_refresh_token)
      assert id == to_string(member.id)
      assert user
    end

    test "refresh_tokens rejects a refresh token of an inactive member", %{member: member} do
      {:ok, _member, _access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:ok, _} = QueryManager.update(member, inactive: true)

      assert {:error, [%{message: "invalid token"}]} = Auth.refresh_tokens(nil, refresh_token)
    end

    test "SSO refresh tokens do not resolve a resource", %{user: user} do
      {:ok, _user, access_token, refresh_token} = Auth.create_tokens(user, "sso")

      assert {:ok, _user, _claims} = ArkeAuth.SSOGuardian.resource_from_token(access_token)

      assert {:error, :invalid_token_type} =
               ArkeAuth.SSOGuardian.resource_from_token(refresh_token)
    end

    test "member data cannot override the id or project claims", %{member: member} do
      forged = %{member | data: Map.merge(member.data, %{id: "other", project: "arke_system"})}

      {:ok, %{id: id, project: project}} = ArkeAuth.Guardian.subject_for_token(forged, %{})

      assert id == to_string(member.id)
      assert project == :test_schema
    end

    test "change_password", %{user: user} = _context do
      Auth.change_password(user, "password", "new_password")

      {:ok, %Arke.Core.Unit{} = updated_pwd_user, access_token, refresh_token} =
        Auth.validate_credentials("test", "new_password", :test_schema)

      {:error, [%{context: _c, message: msg}]} =
        Auth.validate_credentials("test", "wrong_password", :test_schema)

      assert msg == "unauthorized"
    end

    test "change_password (error)", %{user: user} = _context do
      assert {:error, [%{context: "auth", message: "invalid attribute format"}]} ==
               Auth.change_password(user, "password", 1234)
    end
  end
end
