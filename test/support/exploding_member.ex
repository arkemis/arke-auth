defmodule ArkeAuth.Test.ExplodingMember do
  @moduledoc """
  Member-group arke whose create always fails after the row is written, to
  prove the signup pipeline rolls the nested `:arke_system` user back instead
  of orphaning it.
  """
  use Arke.System

  arke id: :exploding_member do
    parameter(:arke_system_user, :dynamic, required: true)
  end

  after_write :explode, on: :create

  defp explode(_hook), do: {:error, [%{context: "member_test", message: "boom"}]}

  def register() do
    [] =
      Arke.handle_manager(
        [arke_from_attr() |> Map.update!(:id, &to_string/1)],
        :arke_system,
        :arke
      )

    Arke.Boundary.GroupManager.add_link(
      :arke_auth_member,
      :arke_system,
      :arke_list,
      :exploding_member,
      %{}
    )

    :ok
  end
end
