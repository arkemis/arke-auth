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

defmodule ArkeAuth.Core.MemberToken do
  @moduledoc """
  Single-use login tokens for a member (`signin?token=`), e.g. the links of
  an export or of a welcome mail.

  A token lives only in `ArkeAuth.Boundary.TokenStore`, keyed by an HMAC of
  the token, so it cannot be read back after `issue/3` returns it: issue a new
  one whenever a link is needed. Tokens are lost when the whole cluster
  restarts. The member's `auth_token` field is no longer read.

      config :arke_auth, ArkeAuth.Core.MemberToken,
        ttl_seconds: 604_800   # 7 days, at most 30 days
  """
  alias ArkeAuth.Boundary.TokenStore
  alias ArkeAuth.Utils.TokenCrypto
  alias Arke.Utils.ErrorGenerator, as: Error

  @default_ttl 7 * 86_400
  @max_ttl 30 * 86_400

  @doc """
  A new token that signs in as `member_id` once, within `ttl_seconds`
  (default from config, at most 30 days).
  """
  @spec issue(atom(), term(), pos_integer() | nil) ::
          {:ok, String.t()} | Arke.Utils.ErrorGenerator.t()
  def issue(project, member_id, ttl_seconds \\ nil) do
    case ttl_seconds || default_ttl() do
      ttl when is_integer(ttl) and ttl > 0 and ttl <= @max_ttl ->
        token = TokenCrypto.random_token()
        :ok = TokenStore.put(store_key(project, token), %{member_id: to_string(member_id)}, ttl)
        {:ok, token}

      _ ->
        Error.create(:auth, "member token ttl exceeds maximum")
    end
  end

  @doc "The member id of `token`, consuming it. Only one use succeeds."
  @spec consume(atom(), term()) :: {:ok, String.t()} | Arke.Utils.ErrorGenerator.t()
  def consume(project, token) when is_binary(token) do
    case TokenStore.take(store_key(project, token)) do
      %{member_id: member_id} -> {:ok, member_id}
      nil -> Error.create(:auth, "invalid token")
    end
  end

  def consume(_project, _token), do: Error.create(:auth, "invalid token")

  @doc "Revokes every token of `member_id` in `project`."
  @spec revoke_all_for_member(atom(), term()) :: :ok
  def revoke_all_for_member(project, member_id),
    do: TokenStore.delete_match({:member_token, project, :_}, %{member_id: to_string(member_id)})

  @doc """
  Raises unless the configured `ttl_seconds` is a positive integer of at most
  30 days. Called when `ArkeAuth.Application` starts.
  """
  @spec validate_config!() :: :ok
  def validate_config!() do
    case default_ttl() do
      ttl when is_integer(ttl) and ttl > 0 and ttl <= @max_ttl ->
        :ok

      ttl ->
        raise ArgumentError,
              "config :arke_auth, #{inspect(__MODULE__)}, ttl_seconds: must be a positive " <>
                "integer of at most #{@max_ttl} (30 days), got: #{inspect(ttl)}"
    end
  end

  defp default_ttl(),
    do:
      Application.get_env(:arke_auth, __MODULE__, [])
      |> Keyword.get(:ttl_seconds, @default_ttl)

  defp store_key(project, token),
    do: {:member_token, project, TokenCrypto.hmac(:member_token, token)}
end
