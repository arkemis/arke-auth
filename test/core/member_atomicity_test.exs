defmodule ArkeAuth.MemberAtomicityTest do
  @moduledoc """
  Phase 4 of PLAN-transactions acceptance: a member insert failure leaves no
  `:arke_system` user behind (before transactions it orphaned one, occupying
  the unique username forever).
  """
  use ArkeAuth.RepoCase

  test "a failing member insert leaves no orphan arke_system user" do
    member_model = ArkeManager.get(:exploding_member, :arke_system)

    assert {:error, [%{message: "boom"}]} =
             QueryManager.create(:test_schema, member_model, %{
               arke_system_user: %{
                 "username" => "orphan_check",
                 "password" => "password",
                 "email" => "orphan@arke.test"
               }
             })

    assert QueryManager.get_by(project: :arke_system, arke_id: :user, username: "orphan_check") ==
             nil

    assert QueryManager.filter_by(project: :test_schema, arke_id: :exploding_member) == []

    {:ok, _} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: "orphan_check",
        password: "password",
        email: "orphan@arke.test"
      })
  end
end
