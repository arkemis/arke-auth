defmodule ArkeAuth.Core.LoginLockoutTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Boundary.AttemptLimiter

  @username "lockout_user"

  setup do
    previous = Application.get_env(:arke_auth, ArkeAuth.Core.Auth)
    Application.put_env(:arke_auth, ArkeAuth.Core.Auth, max_failed_logins: 3, lockout_seconds: 60)

    on_exit(fn ->
      AttemptLimiter.reset({:login, @username})
      AttemptLimiter.reset({:login, "nobody"})

      if previous,
        do: Application.put_env(:arke_auth, ArkeAuth.Core.Auth, previous),
        else: Application.delete_env(:arke_auth, ArkeAuth.Core.Auth)
    end)

    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: @username,
        password: "password",
        email: "lockout@arke.test"
      })

    {:ok, _member} =
      QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
        arke_system_user: to_string(user.id)
      })

    :ok
  end

  describe "validate_credentials/3 lockout (ARKE-AUTH-10)" do
    test "locks the account after max_failed_logins wrong passwords" do
      for _ <- 1..3, do: assert({:error, _} = login("wrong"))

      assert {:error, [%{context: "auth", message: "unauthorized"}]} = login("password")
    end

    test "the lock is per account and case-insensitive" do
      for _ <- 1..3, do: login("wrong")

      assert {:error, _} =
               Auth.validate_credentials(String.upcase(@username), "password", :test_schema)

      AttemptLimiter.reset({:login, @username})
      assert {:ok, _, _, _} = login("password")
    end

    test "a successful login clears the failures" do
      for _ <- 1..2, do: login("wrong")
      assert {:ok, _, _, _} = login("password")

      for _ <- 1..2, do: login("wrong")
      assert {:ok, _, _, _} = login("password")
    end

    test "unknown usernames are counted as well" do
      for _ <- 1..3, do: Auth.validate_credentials("nobody", "x", :test_schema)
      assert AttemptLimiter.count({:login, "nobody"}) == 3
    end

    test "can be disabled" do
      Application.put_env(:arke_auth, ArkeAuth.Core.Auth, max_failed_logins: false)

      for _ <- 1..4, do: login("wrong")
      assert {:ok, _, _, _} = login("password")
    end

    test "a non-string password is rejected without crashing" do
      assert {:error, _} = Auth.validate_credentials(@username, 1234, :test_schema)
    end
  end

  defp login(password), do: Auth.validate_credentials(@username, password, :test_schema)
end
