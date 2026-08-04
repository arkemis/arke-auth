defmodule ArkeAuth.GuardianTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.{Guardian, SSOGuardian}

  setup do
    user_model = ArkeManager.get(:user, :arke_system)

    {:ok, user} =
      QueryManager.create(:arke_system, user_model, %{
        username: "guardian",
        password: "password",
        email: "guardian@arke.test"
      })

    member_model = ArkeManager.get(:super_admin, :arke_system)

    {:ok, member} =
      QueryManager.create(:test_schema, member_model, %{arke_system_user: to_string(user.id)})

    %{user: user, member: member}
  end

  defp claims_for(member),
    do: %{"sub" => %{"id" => to_string(member.id), "project" => "test_schema"}}

  describe "token validation" do
    test "a refresh token is rejected where an access token is required", %{member: member} do
      {:ok, _resource, _access, refresh} = Auth.create_tokens(Auth.format_member(member))

      assert {:error, "typ"} = Guardian.decode_and_verify(refresh, %{"typ" => "access"})
    end

    test "a tampered token is rejected", %{member: member} do
      {:ok, _resource, access, _refresh} = Auth.create_tokens(Auth.format_member(member))

      assert {:error, :invalid_token} = Guardian.decode_and_verify(access <> "tampered")
    end

    test "the two guardians do not accept each other's tokens", %{member: member, user: user} do
      {:ok, _resource, member_token, _refresh} = Auth.create_tokens(Auth.format_member(member))
      {:ok, _resource, sso_token, _refresh} = Auth.create_tokens(user, "sso")

      assert {:error, :invalid_token} = SSOGuardian.decode_and_verify(member_token)
      assert {:error, :invalid_token} = Guardian.decode_and_verify(sso_token)
    end
  end

  describe "check_member/1" do
    test "an inactive member is unauthorized" do
      assert Guardian.check_member(%{data: %{inactive: true}}) == {:error, :unauthorized}
    end

    test "any other member passes", %{member: member} do
      assert Guardian.check_member(member) == {:ok, member}
    end
  end

  describe "resource_from_claims/1" do
    test "resolves the member of the claimed project", %{member: member} do
      assert {:ok, resolved} = Guardian.resource_from_claims(claims_for(member))
      assert resolved.id == member.id
    end

    test "an unknown member id is unauthorized" do
      claims = %{"sub" => %{"id" => "does-not-exist", "project" => "test_schema"}}

      assert Guardian.resource_from_claims(claims) == {:error, :unauthorized}
    end

    test "an inactive member is unauthorized", %{member: member} do
      {:ok, _inactive} = QueryManager.update(member, inactive: true)

      assert Guardian.resource_from_claims(claims_for(member)) == {:error, :unauthorized}
    end

    test "a project that is not a loaded atom is unauthorized, not a crash" do
      claims = %{"sub" => %{"id" => "any", "project" => "project_never_loaded_as_an_atom"}}

      assert Guardian.resource_from_claims(claims) == {:error, :unauthorized}
    end
  end

  describe "get_member/2" do
    setup %{member: member} do
      %{conn: ArkeAuth.Guardian.Plug.put_current_resource(Plug.Test.conn(:get, "/"), member)}
    end

    defp put_impersonate_config(value) do
      config = Application.get_env(:arke_auth, ArkeAuth.Guardian)
      on_exit(fn -> Application.put_env(:arke_auth, ArkeAuth.Guardian, config) end)

      Application.put_env(
        :arke_auth,
        ArkeAuth.Guardian,
        Keyword.put(config, :enable_impersonate, value)
      )
    end

    test "returns the current resource", %{conn: conn, member: member} do
      assert Guardian.get_member(conn).id == member.id
    end

    test "ignores impersonate: true while impersonation is disabled", %{
      conn: conn,
      member: member
    } do
      put_impersonate_config(false)
      impersonated = other_member()
      conn = ArkeAuth.Guardian.Plug.put_current_resource(conn, impersonated, key: :impersonate)

      resolved = Guardian.get_member(conn, impersonate: true)

      assert resolved.id == member.id
      refute Map.get(resolved, :impersonate)
    end

    test "returns the impersonated member, flagged, once enabled", %{conn: conn} do
      put_impersonate_config(true)
      impersonated = other_member()
      conn = ArkeAuth.Guardian.Plug.put_current_resource(conn, impersonated, key: :impersonate)

      resolved = Guardian.get_member(conn, impersonate: true)

      assert resolved.id == impersonated.id
      assert resolved.impersonate == true
    end

    test "falls back to the current resource when nobody is impersonated", %{
      conn: conn,
      member: member
    } do
      put_impersonate_config(true)

      resolved = Guardian.get_member(conn, impersonate: true)

      assert resolved.id == member.id
      refute Map.get(resolved, :impersonate)
    end
  end

  defp other_member do
    user_model = ArkeManager.get(:user, :arke_system)

    {:ok, user} =
      QueryManager.create(:arke_system, user_model, %{
        username: "impersonated",
        password: "password",
        email: "impersonated@arke.test"
      })

    member_model = ArkeManager.get(:super_admin, :arke_system)

    {:ok, member} =
      QueryManager.create(:test_schema, member_model, %{arke_system_user: to_string(user.id)})

    member
  end
end
