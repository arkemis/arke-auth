defmodule ArkeAuth.Core.TemporaryTokenTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Core.TemporaryToken

  # NaiveDateTime.utc_now/0 is sampled once in the lib and once here, so every
  # expiry is asserted as a range.
  defp ttl_seconds(token),
    do: NaiveDateTime.diff(token.data.expiration_datetime, NaiveDateTime.utc_now())

  defp assert_ttl(token, seconds), do: assert(ttl_seconds(token) in (seconds - 5)..seconds)

  describe "generate_token/4 expiry" do
    test "defaults to 1800 seconds" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema)

      assert_ttl(token, 1800)
    end

    test "the default is configurable" do
      on_exit(fn -> Application.delete_env(:arke_auth, :temporary_token_expiration) end)
      Application.put_env(:arke_auth, :temporary_token_expiration, 120)

      {:ok, token} = TemporaryToken.generate_token(:test_schema)

      assert_ttl(token, 120)
    end

    test "accepts a %{days: d} duration" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, %{days: 1})

      assert_ttl(token, 86_400)
    end

    test "accepts a %{minutes: m} duration" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, %{minutes: 30})

      assert_ttl(token, 1800)
    end

    # Clause order makes the %{days:, minutes:} clause unreachable: the
    # %{days: d} clause above matches first and the minutes are dropped. No
    # consumer passes both, so this records the behaviour rather than fixing it.
    test "a duration with both keys silently ignores the minutes" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, %{days: 1, minutes: 30})

      assert_ttl(token, 86_400)
    end

    test "accepts a plain number of seconds" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, 45)

      assert_ttl(token, 45)
    end

    test "0 means zero seconds, not the default" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, 0)

      assert_ttl(token, 0)
    end
  end

  describe "generate_token/4 payload" do
    test "is not reusable unless asked" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema)
      {:ok, reusable} = TemporaryToken.generate_token(:test_schema, nil, true)

      assert token.data.is_reusable == false
      assert reusable.data.is_reusable == true
    end

    test "carries extra opts through" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, nil, false, id: "fixed_token_id")

      assert token.id == :fixed_token_id
    end
  end

  describe "generate_auth_token/5" do
    setup do
      {:ok, user} =
        QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
          username: "temp",
          password: "password",
          email: "temp@arke.test"
        })

      {:ok, member} =
        QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
          arke_system_user: to_string(user.id)
        })

      %{member: member}
    end

    # a unit stores `member.id` verbatim, so link_member is the atom here and a
    # binary in the test below — compare with to_string/1, never ==
    test "links the member given a unit", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member)

      assert token.data.link_member == member.id
      assert_ttl(token, 1800)
    end

    test "links the member given an id", %{member: member} do
      {:ok, token} =
        TemporaryToken.generate_auth_token(:test_schema, to_string(member.id), %{minutes: 5})

      assert token.data.link_member == to_string(member.id)
      assert_ttl(token, 300)
    end
  end
end
