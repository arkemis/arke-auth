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

defmodule ArkeAuth.Core.TemporaryToken do
  @moduledoc """
  Documentation for `TemporaryToken`.
  """

  alias Arke.QueryManager
  alias Arke.Boundary.ArkeManager

  use Arke.System

  arke id: :temporary_token do
  end

  def generate_token(project, duration \\ nil, is_reusable \\ false, opts \\ []) do
    temp_arke = ArkeManager.get(:temporary_token, project)
    expiration_datetime = calculate_expiration_datetime(duration)
    data = [expiration_datetime: expiration_datetime, is_reusable: is_reusable] ++ opts
    QueryManager.create(project, temp_arke, data)
  end

  def generate_auth_token(project, member, duration \\ nil, is_reusable \\ false, opts \\ [])

  def generate_auth_token(project, member, duration, is_reusable, opts) when is_map(member),
    do: generate_auth_token(project, member.id, duration, is_reusable, opts)

  def generate_auth_token(project, member_id, duration, is_reusable, opts) do
    temp_arke = ArkeManager.get(:temporary_token, project)
    expiration_datetime = calculate_expiration_datetime(duration)

    data =
      [link_member: member_id, expiration_datetime: expiration_datetime, is_reusable: is_reusable] ++
        opts

    QueryManager.create(project, temp_arke, data)
  end

  defp calculate_expiration_datetime(duration) when is_nil(duration),
    do:
      add_from_now(
        Application.get_env(:arke_auth, :temporary_token_expiration, 1800)
        |> to_string()
      )

  defp calculate_expiration_datetime(%{days: days}), do: add_from_now(days * 86400)
  defp calculate_expiration_datetime(%{minutes: minutes}), do: add_from_now(minutes * 60)

  defp calculate_expiration_datetime(%{days: days, minutes: minutes}),
    do: add_from_now(days * 86400 + minutes * 60)

  defp calculate_expiration_datetime(duration), do: add_from_now(duration)

  defp add_from_now(seconds) when is_binary(seconds),
    do: String.to_integer(seconds) |> add_from_now

  defp add_from_now(seconds), do: NaiveDateTime.utc_now() |> NaiveDateTime.add(seconds, :second)
end
