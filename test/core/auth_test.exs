defmodule AuthTest do
  use ExUnit.Case

  def create_user(context) do
    user_model = ArkeManager.get(:user, :arke_system)
    QueryManager.create(:test_schema, user_model, get_user_params())
    :ok
  end

  describe "ArkeAuth" do
    setup [:create_user, :get_user]

    test "update", %{user: user} = _context do
      new_data = %{type: "admin"}
      {:ok, edited_user} = Auth.update(user, new_data)
      assert user.data.type != edited_user.data.type

      delete_user()
    end

    test "validate_credentials", %{user: user} = _context do
      {:ok, updated_user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      assert updated_user.id == user.id

      delete_user()
    end

    test "validate_credentials (error)" do
      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("wrong_username", "password", :test_schema)

      assert {:error, [%{context: "auth", message: "unauthorized"}]} ==
               Auth.validate_credentials("test", "wrong_password", :test_schema)

      delete_user()
    end

    test "refresh_tokens" do
      {:ok, %Arke.Core.Unit{} = user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:ok, new_access_token, new_refresh_token} = Auth.refresh_tokens(user, refresh_token)
      assert new_access_token != access_token and new_refresh_token != refresh_token

      delete_user()
    end

    test "refresh_tokens (error)" do
      {:ok, user, access_token, refresh_token} =
        Auth.validate_credentials("test", "password", :test_schema)

      {:error, [%{context: _c, message: msg}]} = Auth.refresh_tokens(user, access_token)
      assert assert msg == "invalid token"

      delete_user()
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

    test "change_password", %{user: user} = _context do
      Auth.change_password(user, "password", "new_password")

      {:ok, %Arke.Core.Unit{} = updated_pwd_user, access_token, refresh_token} =
        Auth.validate_credentials("test", "new_password", :test_schema)

      {:error, [%{context: _c, message: msg}]} =
        Auth.validate_credentials("test", "wrong_password", :test_schema)

      assert msg == "unauthorized"

      delete_user()
    end

    test "change_password (error)", %{user: user} = _context do
      assert {:error, [%{context: "auth", message: "invalid attribute format"}]} ==
               Auth.change_password(user, "password", 1234)

      delete_user()
    end
  end
end
