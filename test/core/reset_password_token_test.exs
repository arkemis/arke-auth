defmodule ArkeAuth.ResetPasswordTokenTest do
  use ArkeAuth.RepoCase

  defp create(data),
    do:
      QueryManager.create(
        :test_schema,
        ArkeManager.get(:reset_password_token, :arke_system),
        data
      )

  describe "before_load/2 on create" do
    test "generates a url-safe token and a 2 week expiry" do
      {:ok, token} = create(user_id: "user_1")

      assert token.data.user_id == "user_1"
      # 22 random bytes, base64url without padding; the lib's `case: :lower` is
      # a no-op for url_encode64, so the token is mixed case
      assert token.data.token =~ ~r|^[A-Za-z0-9_-]+$|
      assert String.length(token.data.token) == 30

      seconds = NaiveDateTime.diff(token.data.expiration, NaiveDateTime.utc_now())
      assert seconds in 1_209_595..1_209_605
    end

    test "the expiry is configurable" do
      on_exit(fn -> Application.delete_env(:arke_auth, :reset_password_token_ttl) end)
      Application.put_env(:arke_auth, :reset_password_token_ttl, days: 1)

      {:ok, token} = create(user_id: "user_1")

      assert NaiveDateTime.diff(token.data.expiration, NaiveDateTime.utc_now()) in 86_395..86_400
    end

    test "every token is distinct" do
      {:ok, first} = create(user_id: "user_1")
      {:ok, second} = create(user_id: "user_2")

      assert first.data.token != second.data.token
    end

    # user_id is fetched with Map.fetch!/2; the KeyError is swallowed by arke's
    # hook dispatch and surfaces as this opaque error, not a validation failure
    test "a missing user_id is not reported as a validation error" do
      assert {:error, "Undefined function"} = create(token: "supplied")
    end
  end
end
