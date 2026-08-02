defmodule ArkeAuth.Core.UserTest do
  use ArkeAuth.RepoCase

  describe "User" do
    test "create user" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password", email: "user@arke.test"]

      {:ok, unit} = QueryManager.create(:test_schema, user_model, data)
      db_user = QueryManager.get_by(id: unit.id, project: :test_schema)

      assert unit.data.username == "arke_auth_user"
      assert unit.arke_id == :user
      assert unit.id == db_user.id

      QueryManager.delete(:test_schema, unit)
      assert QueryManager.get_by(id: unit.id, project: :test_schema) == nil
    end

    test "create user error" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password"]

      {:error, msg} = QueryManager.create(:test_schema, user_model, data)
      assert msg == [%{context: "parameter_validation", message: "email: is required"}]
    end

    test "check_password" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password", email: "user@arke.test"]

      {:ok, unit} = QueryManager.create(:test_schema, user_model, data)

      assert User.check_password(unit, "password") == {:ok, unit}

      assert User.check_password(unit, "invalid") ==
               {:error, [%{context: "auth", message: "invalid password"}]}
    end

    test "update_password" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password", email: "user@arke.test"]

      {:ok, unit} = QueryManager.create(:test_schema, user_model, data)
      assert User.check_password(unit, "password") == {:ok, unit}

      {:ok, new_user} = User.update_password(unit, "new_password")

      assert new_user.id == unit.id

      assert User.check_password(new_user, "password") ==
               {:error, [%{context: "auth", message: "invalid password"}]}

      assert User.check_password(new_user, "new_password") == {:ok, new_user}
    end
  end
end
