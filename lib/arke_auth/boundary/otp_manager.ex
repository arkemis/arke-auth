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

defmodule ArkeAuth.Boundary.OtpManager do
  @moduledoc false
  use Arke.Boundary.UnitManager
  alias ArkeAuth.Core.Otp
  alias Arke.QueryManager

  manager_id(:otp)

  def get_code(project, member, action \\ "signin")

  def get_code(project, member, action) when is_atom(action),
    do: get_code(project, member, to_string(action))

  def get_code(project, member, action) do
    case System.get_env("OTP_BYPASS_CODE") do
      nil ->
        get_member_code(project, member, action)

      "" ->
        get_member_code(project, member, action)

      value ->
        %{
          data: %{
            code: value,
            expiry_datetime: NaiveDateTime.utc_now() |> NaiveDateTime.add(300, :second)
          }
        }
    end
  end

  defp get_member_code(project, member, action) do
    QueryManager.get_by(
      project: project,
      arke: "otp",
      id: Otp.parse_otp_id(action, member.id),
      action: action
    )
  end

  def delete_otp(%Arke.Core.Unit{metadata: %{project: project}} = unit),
    do: QueryManager.delete(project, unit)

  def delete_otp(_unit), do: nil
end
