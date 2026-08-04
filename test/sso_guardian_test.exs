defmodule ArkeAuth.SSOGuardianTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.SSOGuardian

  setup do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: "sso",
        password: "password",
        email: "sso@arke.test"
      })

    %{user: user}
  end

  test "the token carries the user data minus the password hash", %{user: user} do
    {:ok, token, _claims} = SSOGuardian.encode_and_sign(user, %{})
    {:ok, claims} = SSOGuardian.decode_and_verify(token)

    refute Map.has_key?(claims["sub"], "password_hash")
    assert claims["sub"]["username"] == "sso"
    assert claims["sub"]["id"] == to_string(user.id)
  end

  describe "resource_from_claims/1" do
    test "resolves the arke_system user", %{user: user} do
      claims = %{"sub" => %{"id" => to_string(user.id)}}

      assert {:ok, resolved} = SSOGuardian.resource_from_claims(claims)
      assert resolved.id == user.id
    end

    test "an unknown user is unauthorized" do
      claims = %{"sub" => %{"id" => "does-not-exist"}}

      assert SSOGuardian.resource_from_claims(claims) == {:error, :unauthorized}
    end

    test "a member id is not an SSO subject", %{user: user} do
      {:ok, member} =
        QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
          arke_system_user: to_string(user.id)
        })

      claims = %{"sub" => %{"id" => to_string(member.id)}}

      assert SSOGuardian.resource_from_claims(claims) == {:error, :unauthorized}
    end
  end
end
