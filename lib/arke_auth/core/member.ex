# Copyright 2023 Arkemis S.r.l.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule ArkeAuth.Core.Member do
  alias Arke.QueryManager
  alias Arke.Boundary.ArkeManager
  alias Arke.Utils.ErrorGenerator, as: Error

  @moduledoc """
  Documentation for `Member`.
  """
  use Arke.System.Group

  group id: "arke_auth_member" do
  end

  def on_unit_load(_arke, data, _persistence_fn), do: {:ok, data}
  def before_unit_load(_arke, data, _persistence_fn), do: {:ok, data}
  def on_unit_validate(_arke, unit), do: {:ok, unit}

  # TODO Handle user validation (if user exists)
  def before_unit_validate(_arke, %{data: %{arke_system_user: arke_system_user}} = unit)
      when is_binary(arke_system_user) do
    {:ok, unit}
  end

  # TODO Handle user validation (if user already exists and user data validation)
  def before_unit_validate(_arke, %{data: %{arke_system_user: arke_system_user}} = unit)
      when is_map(arke_system_user) do
    {:ok, unit}
  end

  def on_unit_create(_arke, unit), do: {:ok, unit}

  def before_unit_create(_arke, %{data: %{arke_system_user: arke_system_user}} = unit)
      when is_map(arke_system_user) do
    arke_user = ArkeManager.get(:user, :arke_system)

    user_data =
      Enum.map(arke_system_user, fn {key, value} -> {String.to_existing_atom(key), value} end)

    Arke.QueryManager.create(:arke_system, arke_user, user_data)
    |> case do
      {:ok, user} ->
        unit = Arke.Core.Unit.update(unit, arke_system_user: user.id)
        {:ok, unit}

      {:error, error} ->
        {:error, error}
    end
  end

  def before_unit_create(_arke, unit), do: {:ok, unit}

  # The linked user is global: it is shared by every member of that person in
  # every project. Updating a member may therefore touch only an allow-list of
  # profile fields of that user, never its identity or credentials, and may not
  # re-point the member at another user.
  @default_user_update_fields [:first_name, :last_name, :phone_number]
  @never_updatable_user_fields ["password", "password_hash"]

  def before_unit_update(_arke, %{data: %{arke_system_user: new_user}} = unit)
      when is_map(new_user) do
    linked_user_id = linked_user_id(unit)

    with %Arke.Core.Unit{} = user <- get_linked_user(linked_user_id),
         {:ok, user_data} <- user_update_data(user, new_user) do
      unit = Arke.Core.Unit.update(unit, arke_system_user: linked_user_id)

      case user_data do
        [] ->
          {:ok, unit}

        user_data ->
          with {:ok, _user} <- QueryManager.update(user, user_data), do: {:ok, unit}
      end
    end
  end

  def before_unit_update(_arke, %{data: %{arke_system_user: new_user}} = unit)
      when not is_nil(new_user) do
    case to_string(new_user) == to_string(linked_user_id(unit)) do
      true -> {:ok, unit}
      false -> Error.create(:auth, "arke_system_user cannot be changed")
    end
  end

  def before_unit_update(_arke, unit), do: {:ok, unit}

  # The legacy update callbacks do not receive the stored unit, so the linked
  # user is read from the stored member.
  defp linked_user_id(%{id: id, metadata: %{project: project}}) do
    case QueryManager.get_by(project: project, id: to_string(id)) do
      %{data: data} -> Map.get(data, :arke_system_user)
      _ -> nil
    end
  end

  defp linked_user_id(_unit), do: nil

  defp get_linked_user(nil), do: Error.create(:auth, "member has no linked user")

  defp get_linked_user(user_id) do
    case QueryManager.get_by(project: :arke_system, arke_id: :user, id: to_string(user_id)) do
      nil -> Error.create(:auth, "linked user not found")
      user -> user
    end
  end

  # Fields echoed back unchanged are accepted and dropped, so clients may send
  # the user object they read; any other field outside the allow-list fails.
  defp user_update_data(user, new_user) do
    allowed = Map.new(user_update_fields(), &{to_string(&1), &1})
    current = Map.new(user.data, fn {key, value} -> {to_string(key), value} end)

    Enum.reduce_while(new_user, {:ok, []}, fn {key, value}, {:ok, acc} ->
      key = to_string(key)

      cond do
        Map.has_key?(allowed, key) ->
          {:cont, {:ok, [{Map.fetch!(allowed, key), value} | acc]}}

        key not in @never_updatable_user_fields and Map.has_key?(current, key) and
            Map.get(current, key) == value ->
          {:cont, {:ok, acc}}

        true ->
          {:halt, Error.create(:auth, "arke_system_user.#{key} cannot be updated")}
      end
    end)
  end

  defp user_update_fields() do
    Application.get_env(:arke_auth, __MODULE__, [])
    |> Keyword.get(:user_update_fields, @default_user_update_fields)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 in @never_updatable_user_fields))
    |> Enum.map(&String.to_existing_atom/1)
  end

  # Deleting a member only unlinks it from its user. The user is global, so it
  # is deleted only once no member in any project references it any more;
  # otherwise removing someone from one project would destroy their account
  # (and credentials) everywhere else.
  def on_unit_delete(_arke, %{data: data, metadata: %{project: project}} = unit) do
    with user_id when not is_nil(user_id) <- Map.get(data, :arke_system_user),
         user_id = to_string(user_id),
         false <- referenced_by_other_member?(user_id, project, unit.id),
         %Arke.Core.Unit{} = user <-
           QueryManager.get_by(project: :arke_system, arke_id: :user, id: user_id),
         {:ok, _} <- QueryManager.delete(:arke_system, user) do
      {:ok, unit}
    else
      {:error, _} = error -> error
      _ -> {:ok, unit}
    end
  end

  def on_unit_delete(_arke, unit), do: {:ok, unit}

  defp referenced_by_other_member?(user_id, deleted_project, deleted_id) do
    Enum.any?(member_projects(deleted_project), fn project ->
      QueryManager.filter_by(
        project: project,
        group_id: "arke_auth_member",
        arke_system_user: user_id
      )
      |> Enum.any?(fn member ->
        not (project == deleted_project and to_string(member.id) == to_string(deleted_id))
      end)
    end)
  end

  defp member_projects(current_project) do
    projects =
      QueryManager.filter_by(project: :arke_system, arke: :arke_project)
      |> Enum.map(fn %{id: id} -> to_project(id) end)

    Enum.uniq([:arke_system, current_project | projects])
  end

  # Project ids come from the :arke_system project table, not from requests.
  defp to_project(id) when is_atom(id), do: id
  defp to_project(id), do: String.to_atom(to_string(id))

  def before_unit_delete(_arke, unit), do: {:ok, unit}
end
