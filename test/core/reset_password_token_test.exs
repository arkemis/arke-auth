defmodule ArkeAuth.ResetPasswordTokenTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.ResetPasswordToken

  setup do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: "reset_owner",
        password: "password",
        email: "reset@arke.test"
      })

    %{user: user}
  end

  test "a token verifies to its user", %{user: user} do
    {:ok, %{token: token, user_id: user_id}} = ResetPasswordToken.issue(user)

    assert user_id == to_string(user.id)
    assert {:ok, %{id: id}} = ResetPasswordToken.verify(token)
    assert to_string(id) == to_string(user.id)
  end

  test "nothing is stored", %{user: user} do
    {:ok, _} = ResetPasswordToken.issue(user)
    assert ArkeManager.get(:reset_password_token, :arke_system) == nil
  end

  test "the token does not carry the password hash", %{user: user} do
    {:ok, %{token: token}} = ResetPasswordToken.issue(user)
    [payload, _signature] = String.split(token, ".")
    {:ok, payload} = Base.url_decode64(payload, padding: false)

    refute payload =~ user.data.password_hash
  end

  test "a tampered token is refused", %{user: user} do
    {:ok, %{token: token}} = ResetPasswordToken.issue(user)
    [payload, signature] = String.split(token, ".")
    {:ok, decoded} = Base.url_decode64(payload, padding: false)
    forged = String.replace(decoded, to_string(user.id), "someone_else")

    assert {:error, _} =
             ResetPasswordToken.verify(
               Base.url_encode64(forged, padding: false) <> "." <> signature
             )

    assert {:error, _} = ResetPasswordToken.verify(payload <> "." <> String.reverse(signature))
    assert {:error, _} = ResetPasswordToken.verify("garbage")
    assert {:error, _} = ResetPasswordToken.verify(nil)
  end

  test "a token stops working once the password changes", %{user: user} do
    {:ok, %{token: token}} = ResetPasswordToken.issue(user)
    {:ok, _} = User.update_password(user, "a_new_password")

    assert {:error, _} = ResetPasswordToken.verify(token)
  end

  test "an expired token is refused", %{user: user} do
    put_ttl(seconds: 1)
    {:ok, %{token: token}} = ResetPasswordToken.issue(user)
    Process.sleep(2_100)

    assert {:error, _} = ResetPasswordToken.verify(token)
  end

  test "a token of a deleted user is refused", %{user: user} do
    {:ok, %{token: token}} = ResetPasswordToken.issue(user)
    QueryManager.delete(:arke_system, user)

    assert {:error, _} = ResetPasswordToken.verify(token)
  end

  test "the ttl is at most 2 weeks" do
    put_ttl(weeks: 3)
    assert_raise ArgumentError, &ResetPasswordToken.validate_config!/0

    put_ttl(days: 14, seconds: 1)
    assert_raise ArgumentError, &ResetPasswordToken.validate_config!/0

    put_ttl(fortnights: 1)
    assert_raise ArgumentError, &ResetPasswordToken.validate_config!/0

    put_ttl(days: 1)
    assert ResetPasswordToken.validate_config!() == :ok
    assert ResetPasswordToken.ttl_seconds() == 86_400
  end

  defp put_ttl(ttl) do
    previous = Application.get_env(:arke_auth, :reset_password_token_ttl)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:arke_auth, :reset_password_token_ttl, previous),
        else: Application.delete_env(:arke_auth, :reset_password_token_ttl)
    end)

    Application.put_env(:arke_auth, :reset_password_token_ttl, ttl)
  end
end
