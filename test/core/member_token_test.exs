defmodule ArkeAuth.Core.MemberTokenTest do
  use ArkeAuth.RepoCase

  import ExUnit.CaptureLog

  alias ArkeAuth.Core.MemberToken

  setup do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: "member_token_owner",
        password: "password",
        email: "member_token@arke.test"
      })

    {:ok, member} =
      QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
        arke_system_user: to_string(user.id)
      })

    %{member: member}
  end

  test "a token signs in as its member once", %{member: member} do
    {:ok, token} = MemberToken.issue(:test_schema, member.id)

    assert MemberToken.consume(:test_schema, token) == {:ok, to_string(member.id)}
    assert {:error, [%{message: "invalid token"}]} = MemberToken.consume(:test_schema, token)
  end

  test "concurrent uses consume the token once", %{member: member} do
    {:ok, token} = MemberToken.issue(:test_schema, member.id)

    results =
      1..20
      |> Enum.map(fn _ -> Task.async(fn -> MemberToken.consume(:test_schema, token) end) end)
      |> Enum.map(&Task.await/1)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
  end

  test "a token expires", %{member: member} do
    {:ok, token} = MemberToken.issue(:test_schema, member.id, 1)
    Process.sleep(1_100)

    assert {:error, _} = MemberToken.consume(:test_schema, token)
  end

  test "a ttl over 30 days is refused", %{member: member} do
    assert {:ok, _} = MemberToken.issue(:test_schema, member.id, 30 * 86_400)

    assert {:error, [%{message: "member token ttl exceeds maximum"}]} =
             MemberToken.issue(:test_schema, member.id, 30 * 86_400 + 1)
  end

  test "the token is bound to its project", %{member: member} do
    {:ok, token} = MemberToken.issue(:test_schema, member.id)
    assert {:error, _} = MemberToken.consume(:arke_system, token)
  end

  test "deactivating or deleting the member revokes its tokens", %{member: member} do
    {:ok, first} = MemberToken.issue(:test_schema, member.id)
    {:ok, _} = QueryManager.update(member, inactive: true)
    assert {:error, _} = MemberToken.consume(:test_schema, first)

    {:ok, second} = MemberToken.issue(:test_schema, member.id)
    QueryManager.delete(:test_schema, member)
    assert {:error, _} = MemberToken.consume(:test_schema, second)
  end

  test "setting the legacy auth_token field logs a deprecation", %{member: member} do
    log = capture_log(fn -> QueryManager.update(member, auth_token: "legacy") end)
    assert log =~ "auth_token is deprecated"
  end

  test "validate_config!/0" do
    previous = Application.get_env(:arke_auth, MemberToken)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:arke_auth, MemberToken, previous),
        else: Application.delete_env(:arke_auth, MemberToken)
    end)

    Application.put_env(:arke_auth, MemberToken, ttl_seconds: 31 * 86_400)
    assert_raise ArgumentError, &MemberToken.validate_config!/0

    Application.put_env(:arke_auth, MemberToken, ttl_seconds: 86_400)
    assert MemberToken.validate_config!() == :ok
  end
end
