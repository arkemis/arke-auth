defmodule ArkeAuth.Core.UserTest do
  use ArkeAuth.RepoCase

  describe "User" do
    test "create user" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password", type: "customer"]

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
      assert msg == [%{context: "parameter_validation", message: "type: is required"}]
    end

    test "check_password" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password", type: "customer"]

      {:ok, unit} = QueryManager.create(:test_schema, user_model, data)

      assert User.check_password(unit, "password") == {:ok, unit}

      assert User.check_password(unit, "invalid") ==
               {:error, [%{context: "auth", message: "invalid password"}]}

      QueryManager.delete(:test_schema, unit)
    end

    test "update_password" do
      user_model = ArkeManager.get(:user, :arke_system)
      data = [username: "arke_auth_user", password: "password", type: "customer"]

      {:ok, unit} = QueryManager.create(:test_schema, user_model, data)
      assert User.check_password(unit, "password") == {:ok, unit}

      {:ok, new_user} = User.update_password(unit, "new_password")

      assert new_user.id == unit.id

      assert User.check_password(new_user, "password") ==
               {:error, [%{context: "auth", message: "invalid password"}]}

      assert User.check_password(new_user, "new_password") == {:ok, new_user}
    end

    test "an update carrying a password stores its hash, never the plain value" do
      user = create_user()

      {:ok, updated} = QueryManager.update(user, password: "rotated_password")

      refute Map.has_key?(updated.data, :password)
      refute updated.data.password_hash == "rotated_password"
      assert {:ok, _} = User.check_password(updated, "rotated_password")

      stored = QueryManager.get_by(project: :test_schema, id: to_string(user.id))
      refute Map.has_key?(stored.data, :password)
      assert {:ok, _} = User.check_password(stored, "rotated_password")
    end

    test "an update cannot set password_hash directly" do
      user = create_user()
      chosen = Bcrypt.hash_pwd_salt("attacker_password")

      assert {:error, [%{context: "auth", message: "password_hash cannot be set directly"}]} =
               QueryManager.update(user, password_hash: chosen)

      stored = QueryManager.get_by(project: :test_schema, id: to_string(user.id))
      assert {:ok, _} = User.check_password(stored, "password")
      assert {:error, _} = User.check_password(stored, "attacker_password")
    end

    test "an update that leaves the credential alone is accepted" do
      user = create_user()

      {:ok, updated} = QueryManager.update(user, first_name: "Renamed")

      assert updated.data.first_name == "Renamed"
      assert updated.data.password_hash == user.data.password_hash
    end
  end

  describe "Auth.update/2" do
    test "strips credentials from a profile update" do
      user = create_user()
      chosen = Bcrypt.hash_pwd_salt("attacker_password")

      {:ok, updated} =
        Auth.update(user, %{first_name: "Profile", password: "x_password", password_hash: chosen})

      assert updated.data.first_name == "Profile"
      assert {:ok, _} = User.check_password(updated, "password")
    end
  end

  defp create_user() do
    user_model = ArkeManager.get(:user, :arke_system)
    data = [username: "arke_auth_user", password: "password", email: "user@arke.test"]
    {:ok, unit} = QueryManager.create(:test_schema, user_model, data)
    unit
  end
end
