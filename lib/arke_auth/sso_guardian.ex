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

defmodule ArkeAuth.SSOGuardian do
  @moduledoc """
  Guardian callbacks valid in a SSO process
  """
  use Guardian, otp_app: :arke_auth

  @doc """
  The resource used to generate the tokens
  """
  def subject_for_token(user, _claims) do
    jwt_data = %{
      id: to_string(user.id)
    }

    sub = Map.merge(jwt_data, Map.drop(user.data, [:password_hash]))
    {:ok, sub}
  end

  def subject_for_token(_, _) do
    {:error, :reason_for_error}
  end

  @doc """
  Get from the token the resource
  """
  def resource_from_claims(claims) do
    id = claims["sub"]["id"]

    case Arke.QueryManager.get_by(project: :arke_system, arke_id: :user, id: id) do
      nil ->
        {:error, :unauthorized}

      user ->
        data = Map.get(user, :data, %{})
        {:ok, user}
    end
  end

  def resource_from_claims(_claims) do
    {:error, :reason_for_error}
  end
end
