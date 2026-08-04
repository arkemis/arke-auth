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

defmodule ArkeAuth.Utils.Permission do
  alias Arke.QueryManager
  alias Arke.Boundary.ArkeManager

  def get_public_permission(%{metadata: %{project: project}} = arke),
    do: get_public_permission(to_string(arke.id), project)

  def get_public_permission(arke_id, project) do
    get_arke_permission(arke_id, project)
    |> get_permission_dict(nil, true)
    |> parse_data()
  end

  def get_member_permission(member, %{metadata: %{project: project}} = arke),
    do: get_member_permission(member, to_string(arke.id), project)

  def get_member_permission(%{impersonate: true} = member, arke_id, project) do
    _parent_list = get_parent_list(member)
    permissions = get_arke_permission(arke_id, project, member)
    member_public_permission = get_permission_dict(permissions, nil, true)
    member_permission = get_permission_dict(permissions, member, false)

    data =
      Application.get_env(:arke_auth, ArkeAuth.Guardian)
      |> Keyword.get(:allowed_methods, nil)

    Map.merge(member_public_permission, member_permission, fn _k, v1, v2 ->
      if v1, do: v1, else: v2
    end)
    |> Map.merge(data, fn _k, existing_value, new_value ->
      cond do
        is_nil(new_value) or is_nil(existing_value) -> nil
        existing_value == false or new_value == false -> false
        existing_value == true and new_value == true -> true
        true -> false
      end
    end)
    |> permission_dict(member)
    |> parse_data
  end

  def get_member_permission(member, arke_id, project) do
    _parent_list = get_parent_list(member)
    permissions = get_arke_permission(arke_id, project, member)
    member_public_permission = get_permission_dict(permissions, nil, true)
    member_permission = get_permission_dict(permissions, member, false)

    Map.merge(member_public_permission, member_permission, fn _k, v1, v2 ->
      if v1, do: v1, else: v2
    end)
    |> permission_dict(member)
    |> parse_data
  end

  defp parse_data(data) do
    if Map.to_list(data) == [] do
      {:error, nil}
    else
      {:ok, data}
    end
  end

  defp get_arke_permission(arke_id, project, member \\ nil) do
    arke_link = ArkeManager.get(:arke_link, :arke_system)
    parent_list = get_parent_list(member)

    QueryManager.query(project: project, arke: arke_link.id)
    |> QueryManager.where(
      parent_id__in: parent_list,
      child_id: to_string(arke_id),
      type: "permission"
    )
    |> QueryManager.all()
  end

  defp get_permission_dict(permission_list, member, is_public) do
    cond =
      if is_public,
        do: fn parent_id -> parent_id == "member_public" end,
        else: fn parent_id -> parent_id != "member_public" end

    case Enum.find(permission_list, fn p -> cond.(p.data.parent_id) end) do
      nil ->
        permission_dict(%{}, member)

      u ->
        permission_dict(u.metadata, member)
    end
  end

  defp get_parent_list(nil), do: ["member_public"]
  defp get_parent_list(member), do: ["member_public", to_string(member.arke_id)]

  defp permission_dict(_data, %{arke_id: :super_admin} = _member),
    do: %{filter: nil, get: true, put: true, post: true, delete: true}

  defp permission_dict(_data, %{data: %{subscription_active: false}}),
    do: %{filter: nil, get: false, put: false, post: false, delete: false}

  defp permission_dict(data, _member) do
    updated_data = for {key, val} <- data, into: %{}, do: {to_string(key), val}
    filter = Map.get(updated_data, "filter", nil)
    get = Map.get(updated_data, "get", false)
    put = Map.get(updated_data, "put", false)
    delete = Map.get(updated_data, "delete", false)
    post = Map.get(updated_data, "post", false)
    child_only = Map.get(updated_data, "child_only", false)

    %{filter: filter, get: get, put: put, delete: delete, post: post, child_only: child_only}
  end
end
