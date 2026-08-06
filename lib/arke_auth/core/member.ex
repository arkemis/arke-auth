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

  group id: "arke_auth_member" do
  end

  before_write :sync_user_create, on: :create
  before_write :sync_user_update, on: :update
  after_write :delete_user, on: :delete

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

  defp sync_user_update(
         %Hook{
           unit:
             %{data: %{arke_system_user: arke_system_user}, metadata: %{project: project}} = unit
         } = hook
       )
       when is_map(arke_system_user) do
    user_data =
      Enum.map(arke_system_user, fn {key, value} -> {String.to_existing_atom(key), value} end)

    # TODO handle without rendundant query
    old_member = QueryManager.get_by(project: project, id: Atom.to_string(unit.id))
    user = QueryManager.get_by(project: :arke_system, id: old_member.data.arke_system_user)

    case QueryManager.update(user, user_data) do
      {:ok, user} ->
        {:ok, %{hook | unit: Arke.Core.Unit.update(unit, arke_system_user: user.id)}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp sync_user_update(hook), do: {:ok, hook}

  defp delete_user(%Hook{unit: unit} = hook) do
    user =
      QueryManager.get_by(project: :arke_system, arke_id: :user, id: unit.data.arke_system_user)

    QueryManager.delete(:arke_system, user)
    {:ok, hook}
  end
end
