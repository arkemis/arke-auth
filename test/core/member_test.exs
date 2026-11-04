defmodule ArkeAuth.Core.MemberTest do
  use ArkeAuth.RepoCase

  setup do
    user = create_user("member_owner", "owner@arke.test")
    member = create_member(:test_schema, user)
    %{user: user, member: member}
  end

  describe "member update (ARKE-AUTH-02)" do
    test "updates allow-listed profile fields of the linked user", %{user: user, member: member} do
      {:ok, member} =
        QueryManager.update(member, arke_system_user: %{"first_name" => "Updated"})

      assert reload_user(user).data.first_name == "Updated"
      assert to_string(member.data.arke_system_user) == to_string(user.id)
    end

    test "rejects a caller-supplied password_hash", %{user: user, member: member} do
      chosen = Bcrypt.hash_pwd_salt("attacker_password")

      assert {:error, [%{message: "arke_system_user.password_hash cannot be updated"}]} =
               QueryManager.update(member, arke_system_user: %{"password_hash" => chosen})

      assert {:ok, _} = User.check_password(reload_user(user), "password")
    end

    test "rejects a password change", %{user: user, member: member} do
      assert {:error, [%{message: "arke_system_user.password cannot be updated"}]} =
               QueryManager.update(member, arke_system_user: %{"password" => "new_password"})

      assert {:ok, _} = User.check_password(reload_user(user), "password")
    end

    test "rejects identity changes", %{user: user, member: member} do
      for {key, value} <- [{"email", "attacker@arke.test"}, {"username", "attacker"}] do
        assert {:error, [%{message: message}]} =
                 QueryManager.update(member, arke_system_user: %{key => value})

        assert message == "arke_system_user.#{key} cannot be updated"
      end

      reloaded = reload_user(user)
      assert reloaded.data.email == "owner@arke.test"
      assert reloaded.data.username == "member_owner"
    end

    test "fails the whole update when one field is not allowed", %{user: user, member: member} do
      assert {:error, _} =
               QueryManager.update(member,
                 arke_system_user: %{"first_name" => "Sneaky", "email" => "attacker@arke.test"}
               )

      refute reload_user(user).data.first_name == "Sneaky"
    end

    test "accepts unchanged identity fields echoed back", %{user: user, member: member} do
      {:ok, _} =
        QueryManager.update(member,
          arke_system_user: %{
            "username" => "member_owner",
            "email" => "owner@arke.test",
            "first_name" => "Echo"
          }
        )

      assert reload_user(user).data.first_name == "Echo"
    end

    test "rejects re-pointing the member at another user", %{user: user, member: member} do
      other = create_user("other_owner", "other@arke.test")

      assert {:error, [%{message: "arke_system_user cannot be changed"}]} =
               QueryManager.update(member, arke_system_user: to_string(other.id))

      stored = QueryManager.get_by(project: :test_schema, id: to_string(member.id))
      assert to_string(stored.data.arke_system_user) == to_string(user.id)
    end

    test "accepts the current user id unchanged", %{user: user, member: member} do
      assert {:ok, _} =
               QueryManager.update(member,
                 arke_system_user: to_string(user.id),
                 first_name: "Member"
               )
    end

    test "the allow-list is configurable but never admits credentials", %{
      user: user,
      member: member
    } do
      previous = Application.get_env(:arke_auth, ArkeAuth.Core.Member)

      Application.put_env(:arke_auth, ArkeAuth.Core.Member,
        user_update_fields: [:email, :password_hash]
      )

      on_exit(fn ->
        if previous,
          do: Application.put_env(:arke_auth, ArkeAuth.Core.Member, previous),
          else: Application.delete_env(:arke_auth, ArkeAuth.Core.Member)
      end)

      {:ok, _} = QueryManager.update(member, arke_system_user: %{"email" => "new@arke.test"})
      assert reload_user(user).data.email == "new@arke.test"

      assert {:error, _} =
               QueryManager.update(member,
                 arke_system_user: %{"password_hash" => Bcrypt.hash_pwd_salt("x")}
               )
    end
  end

  defp create_user(username, email) do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: username,
        password: "password",
        email: email
      })

    user
  end

  defp create_member(project, user) do
    {:ok, member} =
      QueryManager.create(project, ArkeManager.get(:super_admin, :arke_system), %{
        arke_system_user: to_string(user.id)
      })

    member
  end

  defp reload_user(user),
    do: QueryManager.get_by(project: :arke_system, arke_id: :user, id: to_string(user.id))
end
