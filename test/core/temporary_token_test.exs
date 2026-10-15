defmodule ArkeAuth.Core.TemporaryTokenTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Core.TemporaryToken

  # Expiration must fall between before+seconds and after+seconds.
  defp assert_expires_in(seconds, generate) do
    before = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    {:ok, token} = generate.()
    later = NaiveDateTime.utc_now()

    expiration = token.data.expiration_datetime
    assert NaiveDateTime.compare(expiration, NaiveDateTime.add(before, seconds)) != :lt
    assert NaiveDateTime.compare(expiration, NaiveDateTime.add(later, seconds)) != :gt
    token
  end

  defp assert_token_expires_in(seconds, duration),
    do:
      assert_expires_in(seconds, fn -> TemporaryToken.generate_token(:test_schema, duration) end)

  describe "generate_token/2 expiration" do
    test "days" do
      assert_token_expires_in(86_400, %{days: 1})
      assert_token_expires_in(3 * 86_400, %{days: 3})
    end

    test "minutes" do
      assert_token_expires_in(1_800, %{minutes: 30})
    end

    test "days and minutes together add up" do
      assert_token_expires_in(86_400 + 1_800, %{days: 1, minutes: 30})
      assert_token_expires_in(300, %{days: 0, minutes: 5})
    end

    test "seconds as an integer or a string" do
      assert_token_expires_in(90, 90)
      assert_token_expires_in(90, "90")
    end

    test "nil uses the configured default, 1800 seconds when unset" do
      assert_token_expires_in(1_800, nil)

      previous = Application.get_env(:arke_auth, :temporary_token_expiration)
      Application.put_env(:arke_auth, :temporary_token_expiration, 600)

      try do
        assert_token_expires_in(600, nil)
      after
        if previous,
          do: Application.put_env(:arke_auth, :temporary_token_expiration, previous),
          else: Application.delete_env(:arke_auth, :temporary_token_expiration)
      end
    end

    test "the stored expiration is the one returned" do
      token = assert_token_expires_in(86_400 + 1_800, %{days: 1, minutes: 30})
      stored = QueryManager.get_by(id: token.id, project: :test_schema)

      assert NaiveDateTime.compare(
               stored.data.expiration_datetime,
               token.data.expiration_datetime
             ) ==
               :eq
    end
  end

  describe "generate_auth_token/5 expiration" do
    setup do
      user_model = ArkeManager.get(:user, :arke_system)

      {:ok, user} =
        QueryManager.create(:arke_system, user_model, %{
          username: "temp_token_user",
          password: "password",
          email: "temp_token@arke.test"
        })

      {:ok, member} =
        QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
          arke_system_user: to_string(user.id)
        })

      %{member: member}
    end

    test "days and minutes together add up, for a member or its id", %{member: member} do
      for who <- [member, member.id] do
        token =
          assert_expires_in(86_400 + 1_800, fn ->
            TemporaryToken.generate_auth_token(:test_schema, who, %{days: 1, minutes: 30})
          end)

        assert to_string(token.data.link_member) == to_string(member.id)
      end
    end
  end
end
