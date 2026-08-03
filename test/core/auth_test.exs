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
