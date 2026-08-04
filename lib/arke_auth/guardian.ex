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

defmodule ArkeAuth.Guardian do
  @moduledoc """
  Guardian callbacks
  """
  use Guardian, otp_app: :arke_auth

  def get_member(conn, opts \\ []) do
    impersonate = Keyword.get(opts, :impersonate, false)

    enable_impersonate =
      Application.get_env(:arke_auth, ArkeAuth.Guardian)
      |> Keyword.get(:enable_impersonate, false)

    cond do
      impersonate and enable_impersonate -> get_impersonate_resources(conn)
      true -> ArkeAuth.Guardian.Plug.current_resource(conn)
    end
  end

  defp get_impersonate_resources(conn) do
    case ArkeAuth.Guardian.Plug.current_resource(conn, key: :impersonate) do
      nil ->
        ArkeAuth.Guardian.Plug.current_resource(conn)

      member ->
        Map.put(
          member,
          :impersonate,
          true
        )
    end
  end

  @doc """
  The resource used to generate the tokens
  """
  def subject_for_token(member, _claims) do
    jwt_data = %{
      id: to_string(member.id),
      project: member.metadata.project
    }

    sub = Map.merge(jwt_data, member.data)
    {:ok, sub}
  end

  @doc """
  Get from the token the resource
  """
  def resource_from_claims(claims) do
    id = claims["sub"]["id"]
    project = String.to_existing_atom(claims["sub"]["project"])

    case Arke.QueryManager.get_by(project: project, group_id: "arke_auth_member", id: id) do
      nil ->
        {:error, :unauthorized}

      member ->
        check_member(member)
    end
  end

  def check_member(%{data: %{inactive: true}}), do: {:error, :unauthorized}
  def check_member(member), do: {:ok, member}
end
