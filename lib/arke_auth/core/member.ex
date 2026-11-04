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

  @moduledoc """
  Documentation for `Member`.
  """
  use Arke.System.Group
  alias Arke.Hook
  alias Arke.Utils.ErrorGenerator, as: Error

  group id: "arke_auth_member" do
  end

  before_write(:sync_user_create, on: :create)
  before_write(:sync_user_update, on: :update)
  after_write(:delete_user, on: :delete)

  defp sync_user_create(%Hook{unit: %{data: %{arke_system_user: arke_system_user}} = unit} = hook)
       when is_map(arke_system_user) do
    arke_user = ArkeManager.get(:user, :arke_system)

    user_data =
      Enum.map(arke_system_user, fn {key, value} -> {String.to_existing_atom(key), value} end)

    case Arke.QueryManager.create(:arke_system, arke_user, user_data) do
      {:ok, user} ->
        {:ok, %{hook | unit: Arke.Core.Unit.update(unit, arke_system_user: user.id)}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp sync_user_create(hook), do: {:ok, hook}

  # The linked user is global: it is shared by every member of that person in
  # every project. Updating a member may therefore touch only an allow-list of
  # profile fields of that user, never its identity or credentials, and may not
  # re-point the member at another user.
  @default_user_update_fields [:first_name, :last_name, :phone_number]
  @never_updatable_user_fields ["password", "password_hash"]

  defp sync_user_update(%Hook{unit: %{data: %{arke_system_user: new_user}} = unit} = hook)
       when is_map(new_user) do
    linked_user_id = linked_user_id(hook)

    with %Arke.Core.Unit{} = user <- get_linked_user(linked_user_id),
         {:ok, user_data} <- user_update_data(user, new_user) do
      unit = Arke.Core.Unit.update(unit, arke_system_user: linked_user_id)

      case user_data do
        [] ->
          {:ok, %{hook | unit: unit}}

        user_data ->
          with {:ok, _user} <- QueryManager.update(user, user_data),
               do: {:ok, %{hook | unit: unit}}
      end
    end
  end

  defp sync_user_update(%Hook{unit: %{data: %{arke_system_user: new_user}}} = hook)
       when not is_nil(new_user) do
    case to_string(new_user) == to_string(linked_user_id(hook)) do
      true -> {:ok, hook}
      false -> Error.create(:auth, "arke_system_user cannot be changed")
    end
  end

  defp sync_user_update(hook), do: {:ok, hook}

  defp linked_user_id(%Hook{old_unit: %{data: data}}), do: Map.get(data, :arke_system_user)
  defp linked_user_id(_hook), do: nil

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

  defp delete_user(%Hook{unit: unit} = hook) do
    user =
      QueryManager.get_by(project: :arke_system, arke_id: :user, id: unit.data.arke_system_user)

    QueryManager.delete(:arke_system, user)
    {:ok, hook}
  end
end
