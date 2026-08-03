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

defmodule ArkeAuth.Core.Auth do
  @moduledoc """
    `ArkeAuth.Core.Auth` documentation
  """

  alias Arke.QueryManager
  alias ArkeAuth.Core.User
  alias ArkeAuth.{Guardian, SSOGuardian}
  alias Arke.Utils.ErrorGenerator, as: Error

  # todo: add method to validate sso

  ######### UPDATE USER #############
  @doc """
  Update the user data

  ## Parameters
    - user => %Arke.Core.Unit{} => the user to update
    - data => %map => map containing all the data to update

  ## Example
      iex> params = [username: "test", password: "password", type: "customer"]
      ...> user = Arke.QuseryManager.get_by(id: "test")
      ...> ArkeAuth.Core.update(user, params)
  ## Return
      {:ok, %Arke.Core.Unit{}}
      {:error, msg}
  """
  @spec update(user :: Arke.Core.Unit.t(), data :: [ArkeAuth.Core.User.t()]) ::
          {:ok, Arke.Core.Unit.t()} | Arke.Utils.ErrorGenerator.t()
  def update(user, data) do
    with {:ok, user} <- Arke.QueryManager.update(user, check_password_data(data)) do
      {:ok, user}
    else
      err -> err
    end
  end

  defp check_password_data(data) when is_map(data) do
    with true <- Map.has_key?(data, :password) do
      Map.delete(data, :password)
    else
      _ -> data
    end
  end

  ######### CHECK PASSWORD #############
  @doc """
  Implementation for the login. It verify the given username and password

  ## Parameters
    - username => string => user's username
    - password => string => user's password

  ## Example
      iex> ArkeAuth.Core.validate_credentials("test", "password_test")

  ## Return
      {:ok, %ArkeAuth.Core.User{}}
  """
  @spec validate_credentials(username :: String.t(), password :: String.t(), project :: atom()) ::
          {:ok, Arke.Core.Unit.t()} | Arke.Utils.ErrorGenerator.t()
  def validate_credentials(username, password, project \\ :arke_system) do
    case email_password_auth(username, password, :arke_system) do
      {:ok, user} ->
        case get_project_member(project, user) do
          {:ok, member} ->
            {:ok, _resource, access_token, refresh_token} = create_tokens(format_member(member))
            {:ok, member, access_token, refresh_token}

          _ ->
            Error.create(:auth, "unauthorized")
        end

      _ ->
        Error.create(:auth, "unauthorized")
    end
  end

  defp email_password_auth(username, password, project)
       when is_binary(username) and is_binary(password) do
    with {:ok, user} <- get_by_username(username, project), do: verify_password(password, user)
  end

  def get_project_member(project, user) do
    case QueryManager.get_by(
           project: project,
           group_id: "arke_auth_member",
           arke_system_user: user.id
         ) do
      nil ->
        Error.create(:auth, "member not exists")

      member ->
        case Map.get(member.data, :inactive, false) do
          false -> {:ok, member}
          nil -> {:ok, member}
          true -> Error.create(:auth, "member_not_active")
        end
    end
  end

  defp get_by_username(username, project) when is_binary(username) do
    case QueryManager.get_by(project: project, arke_id: :user, username: username) do
      [] ->
        Bcrypt.no_user_verify()
        Error.create(:auth, "login error")

      nil ->
        Bcrypt.no_user_verify()
        Error.create(:auth, "login error")

      unit ->
        {:ok, unit}
    end
  end

  defp verify_password(password, user) when is_binary(password) do
    if Bcrypt.verify_pass(password, user.data.password_hash) do
      {:ok, user}
    else
      Error.create(:auth, "login error")
    end
  end

  ######## END CHECK PW ##########

  #### JWT MANAGEMENT START #####
  def create_tokens(resource, sso \\ "default") do
    with {:ok, access_token} <- create_access_token(resource, sso),
         {:ok, refresh_token} <- create_refresh_token(resource, sso) do
      {:ok, resource, access_token, refresh_token}
    end
  end

  # default ttl of the acess token is 1 week
  defp create_access_token(resource, sso) do
    guardian_module = get_guardian_module(sso)

    case guardian_module.encode_and_sign(resource, %{}) do
      {:ok, token, _claims} -> {:ok, token}
      {:error, type} -> Error.create(:auth, type)
    end
  end

  # create a refresh token for a given user. set the ttl of the token to 4 weeks
  defp create_refresh_token(resource, sso) do
    guardian_module = get_guardian_module(sso)

    case guardian_module.encode_and_sign(resource, %{}, token_type: "refresh") do
      {:ok, token, _claims} -> {:ok, token}
      {:error, type} -> Error.create(:auth, type)
    end
  end

  defp get_guardian_module("sso"), do: SSOGuardian
  defp get_guardian_module(_), do: Guardian

  @doc """
  Create new access_token and refresh_token exchanging the user refresh token

  ## Parameter
    - user => %Arke.Core.Unit{} => the unit struct representing the user
    - token => the refresh_token to exchange

  ## Returns
      {:ok, access_token, refresh_token}
      {:error, msg}
  """
  @spec refresh_tokens(user :: Arke.Core.Unit.t(), token :: String.t()) ::
          {:ok, new_token :: String.t(), refresh_token :: String.t()}
          | Arke.Utils.ErrorGenerator.t()
  def refresh_tokens(user, token) do
    case Guardian.decode_and_verify(token, %{"typ" => "refresh"}) do
      {:ok, _} ->
        with {:ok, _old_stuff, {new_token, _new_claims}} <-
               Guardian.exchange(token, "refresh", "access"),
             {:ok, refresh_token} <- create_refresh_token(user, "default") do
          {:ok, new_token, refresh_token}
        end

      _ ->
        Error.create(:auth, "invalid token")
    end
  end

  #### JWT MANAGEMENT END #####

  #### PASSSWORD MANAGEMENT START #####

  @doc """
  Change the user password

  ## Parameter
    - user => %Arke.Core.Unit{} => the unit struct representing the user
    - old_pwd => string => the old password
    - new_pwd => string => the new password

  ## Return
      {:ok, %Arke.Core.Unit{}}
      {:error, msg}
  """
  @spec change_password(user :: Arke.Core.Unit.t(), old_pwd :: String.t(), new_pwd :: String.t()) ::
          {:ok, Arke.Core.Unit.t()} | Arke.Utils.ErrorGenerator.t()
  def change_password(user, old_pwd, new_pwd)

  def change_password(user, old_pwd, new_pwd) when is_binary(old_pwd) and is_binary(new_pwd) do
    with {:ok, _} <- User.check_password(user, old_pwd),
         {:ok, user} <- User.update_password(user, new_pwd),
         do: {:ok, user},
         else: (error -> error)
  end

  def change_password(_conn, _old_pwd, _new_pwd),
    do: Error.create(:auth, "invalid attribute format")

  #### PASSSWORD MANAGEMENT END #####

  def format_member(member) do
    %{
      id: member.id,
      arke_id: member.arke_id,
      arke_system_user: member.data.arke_system_user,
      data: %{
        email: Map.get(member.data, :email),
        first_name: Map.get(member.data, :first_name),
        last_name: Map.get(member.data, :last_name),
        subscription_active: Map.get(member.data, :subscription_active)
      },
      metadata: member.metadata,
      inserted_at: member.inserted_at,
      updated_at: member.inserted_at
    }
  end
end
