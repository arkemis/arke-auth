defmodule ArkeAuth.Core.TemporaryTokenTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Core.TemporaryToken

  describe "temporary token id (ARKE-AUTH-06)" do
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

    test "generate_token/4 uses a 256-bit random id, not a UUID" do
      {:ok, token} = TemporaryToken.generate_token(:test_schema)
      id = to_string(token.id)

      assert id =~ ~r/^[0-9a-f]{64}$/
      assert QueryManager.get_by(project: :test_schema, arke_id: :temporary_token, id: id)
    end

    test "generate_auth_token/5 uses a 256-bit random id bound to the member", %{member: member} do
      {:ok, token} = TemporaryToken.generate_auth_token(:test_schema, member)

      assert to_string(token.id) =~ ~r/^[0-9a-f]{64}$/
      assert to_string(token.data.link_member) == to_string(member.id)
    end

    test "callers cannot pick the id", %{member: member} do
      {:ok, token} = TemporaryToken.generate_token(:test_schema, nil, false, id: "chosen")
      refute token.id == :chosen

      {:ok, token} =
        TemporaryToken.generate_auth_token(:test_schema, member, nil, false, id: "chosen")

      refute token.id == :chosen
    end
  end
end
