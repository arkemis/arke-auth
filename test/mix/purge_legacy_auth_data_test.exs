defmodule Mix.Tasks.ArkeAuth.PurgeLegacyAuthDataTest do
  use ArkeAuth.RepoCase

  alias Arke.Core.Unit
  alias Mix.Tasks.ArkeAuth.PurgeLegacyAuthData

  # Legacy rows as earlier releases left them: units of arkes that are no
  # longer registered, written straight into the persistence.
  defp legacy_unit(project, id, arke_id) do
    unit = Unit.new(id, %{legacy: true}, arke_id, nil, %{}, nil, nil, nil)
    {:ok, _} = Arke.Test.Persistence.create(project, unit)
  end

  setup do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: "purge_owner",
        password: "password",
        email: "purge@arke.test"
      })

    {:ok, member} =
      QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
        arke_system_user: to_string(user.id)
      })

    {:ok, _} =
      Arke.Test.Persistence.update(:test_schema, %{
        member
        | data: Map.put(member.data, :auth_token, "legacy_link")
      })

    legacy_unit(:test_schema, :legacy_otp, :otp)
    legacy_unit(:test_schema, :legacy_temporary_token, :temporary_token)
    legacy_unit(:arke_system, :legacy_reset_token, :reset_password_token)

    %{member: member, user: user}
  end

  defp member_auth_token(member) do
    QueryManager.get_by(project: :test_schema, id: to_string(member.id)).data
    |> Map.get(:auth_token)
  end

  test "a dry run counts and changes nothing", %{member: member} do
    counts = PurgeLegacyAuthData.purge([:arke_system, :test_schema], false)

    assert counts[:test_schema] == %{
             otp: 1,
             temporary_token: 1,
             reset_password_token: 0,
             member_auth_token: 1
           }

    assert counts[:arke_system].reset_password_token == 1

    assert length(QueryManager.filter_by(project: :test_schema, arke_id: :otp)) == 1
    assert member_auth_token(member) == "legacy_link"
  end

  test "--confirm removes the legacy rows and clears auth_token only", %{
    member: member,
    user: user
  } do
    PurgeLegacyAuthData.purge([:arke_system, :test_schema], true)

    assert QueryManager.filter_by(project: :test_schema, arke_id: :otp) == []
    assert QueryManager.filter_by(project: :test_schema, arke_id: :temporary_token) == []
    assert QueryManager.filter_by(project: :arke_system, arke_id: :reset_password_token) == []
    assert member_auth_token(member) in [nil, ""]

    assert QueryManager.get_by(project: :test_schema, id: to_string(member.id))
    assert QueryManager.get_by(project: :arke_system, arke_id: :user, id: to_string(user.id))

    assert PurgeLegacyAuthData.purge([:arke_system, :test_schema], false)[:test_schema] == %{
             otp: 0,
             temporary_token: 0,
             reset_password_token: 0,
             member_auth_token: 0
           }
  end
end
