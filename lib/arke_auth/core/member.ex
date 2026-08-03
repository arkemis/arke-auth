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
  alias ArkeAuth.Core.Member
  alias Arke.Boundary.ArkeManager

  @moduledoc """
  Documentation for `Member`.
  """
  use Arke.System.Group

  group id: "arke_auth_member" do
  end

  def on_unit_load(arke, data, _persistence_fn), do: {:ok, data}
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

  def before_unit_update(
        _arke,
        %{data: %{arke_system_user: arke_system_user}, metadata: %{project: project}} = unit
      )
      when is_map(arke_system_user) do
    arke_user = ArkeManager.get(:user, :arke_system)

    user_data =
      Enum.map(arke_system_user, fn {key, value} -> {String.to_existing_atom(key), value} end)

    # TODO handle without rendundant query
    old_member = QueryManager.get_by(project: project, id: Atom.to_string(unit.id))
    user = QueryManager.get_by(project: :arke_system, id: old_member.data.arke_system_user)

    QueryManager.update(user, user_data)
    |> case do
      {:ok, user} ->
        unit = Arke.Core.Unit.update(unit, arke_system_user: user.id)
        {:ok, unit}

      {:error, error} ->
        {:error, error}
    end
  end

  def before_unit_update(_arke, unit), do: {:ok, unit}

  def on_unit_delete(_arke, unit) do
    user =
      QueryManager.get_by(project: :arke_system, arke_id: :user, id: unit.data.arke_system_user)

    QueryManager.delete(:arke_system, user)
    {:ok, unit}
  end

  def before_unit_delete(_arke, unit), do: {:ok, unit}

  defp handle_get_permission(member, %{metadata: %{project: project}} = arke) do
    arke_link = ArkeManager.get(:arke_link, :arke_system)

    arke_member_public =
      QueryManager.get_by(project: project, arke_id: "ake", id: "member_public")

    parent_id_list = get_parent_list(member)

    permissions =
      QueryManager.query(project: project, arke: arke_link.id)
      |> QueryManager.where(
        parent_id__in: parent_id_list,
        child_id: Atom.to_string(arke.id),
        type: "permission"
      )
      |> QueryManager.all()

    member_public_permission = get_permission_dict(permissions, true)
    member_permission = get_permission_dict(permissions, false)

    data =
      Map.merge(member_public_permission, member_permission, fn _k, v1, v2 ->
        if v1, do: v1, else: v2
      end)
      |> permission_dict

    if Map.to_list(data) == [] do
      {:error, nil}
    else
      {:ok, data}
    end
  end

  defp permission_dict(data \\ %{}) do
    updated_data = for {key, val} <- data, into: %{}, do: {to_string(key), val}

    filter = Map.get(updated_data, "filter", nil)
    get = Map.get(updated_data, "get", false)
    put = Map.get(updated_data, "put", false)
    delete = Map.get(updated_data, "delete", false)
    post = Map.get(updated_data, "post", false)
    child_only = Map.get(updated_data, "child_only", false)

    %{filter: filter, get: get, put: put, delete: delete, post: post, child_only: child_only}
  end

  defp get_permission_dict(permission_list, is_public \\ false) do
    cond =
      if is_public,
        do: fn parent_id -> parent_id == "member_public" end,
        else: fn parent_id -> parent_id != "member_public" end

    case Enum.find(permission_list, fn p -> cond.(p.parent_id) end) do
      nil ->
        permission_dict()

      u ->
        permission_dict(u.metadata)
    end
  end

  defp get_parent_list(nil), do: ["member_public"]
  defp get_parent_list(member), do: ["member_public", to_string(member.arke_id)]
end
