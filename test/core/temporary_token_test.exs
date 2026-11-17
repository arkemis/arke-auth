defmodule ArkeAuth.Core.TemporaryTokenTest do
  use ArkeAuth.RepoCase

  import ExUnit.CaptureLog

  alias ArkeAuth.Core.TemporaryToken

  setup do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: "token_owner",
        password: "password",
        email: "token@arke.test"
      })

    {:ok, member} =
      QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
        arke_system_user: to_string(user.id)
      })

    %{member: member}
  end

  describe "generation" do
    test "generate_auth_token/5 returns a 256-bit random token bound to the member",
         %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member)

      assert token.id =~ ~r/^[0-9a-f]{64}$/
      assert token.data.link_member == to_string(member.id)
      refute token.data.is_reusable
    end

    test "tokens are not stored in the database", %{member: member} do
      {:ok, _token} = TemporaryToken.generate_auth_token(:test_schema, member)

      assert QueryManager.filter_by(project: :test_schema, arke_id: :temporary_token) == []
      assert ArkeManager.get(:temporary_token, :arke_system) == nil
    end

    test "callers cannot pick the token", %{member: member} do
      {:ok, token} =
        TemporaryToken.generate_auth_token(:test_schema, member, nil, false, id: "chosen")

      refute token.id == "chosen"
      assert {:error, _} = TemporaryToken.verify(:test_schema, "chosen")
    end

    test "extra opts are kept in data", %{member: member} do
      {:ok, token} =
        TemporaryToken.generate_auth_token(:test_schema, member, nil, false, purpose: "invite")

      assert {:ok, %{data: %{purpose: "invite"}}} = TemporaryToken.verify(:test_schema, token.id)
    end

    test "a duration over 30 days is refused", %{member: member} do
      assert {:ok, _} = TemporaryToken.generate_auth_token(:test_schema, member, %{days: 30})

      assert {:error, [%{message: "temporary token duration exceeds 30 days"}]} =
               TemporaryToken.generate_auth_token(:test_schema, member, %{days: 31})

      assert {:error, [%{message: "temporary token duration exceeds 30 days"}]} =
               TemporaryToken.generate_auth_token(:test_schema, member, %{days: 30, minutes: 1})
    end

    test "generate_token/4 still works without a member" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema)
      assert {:ok, %{data: %{link_member: nil}}} = TemporaryToken.verify(:test_schema, token.id)
    end
  end

  describe "verify/3 and consume/2" do
    test "verify/3 checks the member when given", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member)

      assert {:ok, _} = TemporaryToken.verify(:test_schema, token.id, member.id)
      assert {:error, _} = TemporaryToken.verify(:test_schema, token.id, "someone_else")
      assert {:error, _} = TemporaryToken.verify(:other_project, token.id)
    end

    test "an expired token is rejected", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member, 1)
      Process.sleep(1_100)

      assert {:error, _} = TemporaryToken.verify(:test_schema, token.id)
    end

    test "a single-use token is consumed once, even concurrently", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member)

      results =
        1..20
        |> Enum.map(fn _ ->
          Task.async(fn -> TemporaryToken.consume(:test_schema, token.id) end)
        end)
        |> Enum.map(&Task.await/1)

      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert {:error, _} = TemporaryToken.verify(:test_schema, token.id)
    end

    test "a reusable token survives its uses", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member, nil, true)

      assert {:ok, _} = TemporaryToken.consume(:test_schema, token.id)
      assert {:ok, _} = TemporaryToken.consume(:test_schema, token.id)
    end
  end

  describe "revocation" do
    test "revoke/2", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member, nil, true)
      TemporaryToken.revoke(:test_schema, token.id)

      assert {:error, _} = TemporaryToken.verify(:test_schema, token.id)
    end

    test "revoke_all_for_member/2 leaves other members' tokens", %{member: member} do
      {:ok, mine} = TemporaryToken.generate_auth_token(:test_schema, member, nil, true)
      {:ok, theirs} = TemporaryToken.generate_auth_token(:test_schema, "another_member")

      TemporaryToken.revoke_all_for_member(:test_schema, member.id)

      assert {:error, _} = TemporaryToken.verify(:test_schema, mine.id)
      assert {:ok, _} = TemporaryToken.verify(:test_schema, theirs.id)
    end

    test "deactivating the member revokes its tokens", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member, nil, true)
      {:ok, _} = QueryManager.update(member, inactive: true)

      assert {:error, _} = TemporaryToken.verify(:test_schema, token.id)
    end

    test "deleting the member revokes its tokens", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member, nil, true)
      QueryManager.delete(:test_schema, member)

      assert {:error, _} = TemporaryToken.verify(:test_schema, token.id)
    end
  end

  describe "defaults and the legacy field" do
    test "a token lasts 1 day by default", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member)
      seconds = NaiveDateTime.diff(token.data.expiration_datetime, NaiveDateTime.utc_now())

      assert seconds in 86_390..86_400
    end

    test "setting the legacy auth_token field logs a deprecation", %{member: member} do
      log = capture_log(fn -> QueryManager.update(member, auth_token: "legacy") end)
      assert log =~ "auth_token is deprecated"
      assert log =~ "TemporaryToken.generate_auth_token/5"
    end
  end
end
