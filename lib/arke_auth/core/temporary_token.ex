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
  Bearer tokens for magic links (e.g. invitations): whoever holds one signs
  in as the linked member.

  Tokens live only in `ArkeAuth.Boundary.TokenStore`, keyed by an HMAC of the
  token (`ArkeAuth.Utils.TokenCrypto`); the clear token is returned once, to
  the caller that builds the link. They are not units, so the generic unit
  endpoints cannot list them, and they are lost when the whole cluster
  restarts. A token lasts at most #{30} days.
  """
  alias ArkeAuth.Boundary.TokenStore
  alias ArkeAuth.Utils.TokenCrypto
  alias Arke.Utils.ErrorGenerator, as: Error

  @max_seconds 30 * 86_400

  # The token is the bearer secret: 256 bits from a CSPRNG, hex encoded.
  @secret_bytes 32

  @doc """
  A fresh, unguessable token: #{@secret_bytes} random bytes, hex encoded.
  """
  @spec generate_secret() :: String.t()
  def generate_secret(),
    do: :crypto.strong_rand_bytes(@secret_bytes) |> Base.encode16(case: :lower)

  @doc """
  A token that signs in as `member` (a member or its id) for `duration`:
  `nil` (config `:temporary_token_expiration`, default 1800 seconds), a number
  of seconds, `%{days: d}`, `%{minutes: m}` or `%{days: d, minutes: m}`, at
  most 30 days. A reusable token survives its uses; otherwise the first
  sign-in consumes it. Extra `opts` are kept with the token and returned in
  `data`.
  """
  def generate_auth_token(project, member, duration \\ nil, is_reusable \\ false, opts \\ [])

  def generate_auth_token(project, member, duration, is_reusable, opts) when is_map(member),
    do: generate_auth_token(project, member.id, duration, is_reusable, opts)

  def generate_auth_token(project, member_id, duration, is_reusable, opts),
    do: create(project, to_string(member_id), duration, is_reusable, opts)

  @doc deprecated: "Use generate_auth_token/5: a token without a member signs nobody in."
  def generate_token(project, duration \\ nil, is_reusable \\ false, opts \\ []),
    do: create(project, nil, duration, is_reusable, opts)

  @doc """
  The token's data if it exists, has not expired and (when `member_id` is
  given) belongs to that member.
  """
  def verify(project, token, member_id \\ nil) do
    with entry when not is_nil(entry) <- lookup(project, token),
         true <- is_nil(member_id) or entry.link_member == to_string(member_id) do
      {:ok, to_token(project, token, entry)}
    else
      _ -> Error.create(:auth, "invalid token")
    end
  end

  @doc """
  Like `verify/3`, and consumes the token unless it is reusable. Only one of
  two concurrent uses of a single-use token succeeds.
  """
  def consume(project, token) do
    with {:ok, %{data: %{is_reusable: reusable}}} = ok <- verify(project, token) do
      cond do
        reusable -> ok
        TokenStore.take(store_key(project, token)) -> ok
        true -> Error.create(:auth, "invalid token")
      end
    end
  end

  @spec revoke(atom(), String.t()) :: :ok
  def revoke(project, token), do: TokenStore.delete(store_key(project, token))

  @doc "Revokes every token of `member_id` in `project`."
  @spec revoke_all_for_member(atom(), term()) :: :ok
  def revoke_all_for_member(project, member_id),
    do:
      TokenStore.delete_match(
        {:temporary_token, project, :_},
        %{link_member: to_string(member_id)}
      )

  defp create(project, member_id, duration, is_reusable, opts) do
    with {:ok, seconds} <- duration_seconds(duration) do
      token = generate_secret()

      entry = %{
        link_member: member_id,
        is_reusable: is_reusable == true,
        expiration_datetime: NaiveDateTime.utc_now() |> NaiveDateTime.add(seconds, :second),
        opts: opts |> Keyword.delete(:id) |> Map.new()
      }

      :ok = TokenStore.put(store_key(project, token), entry, seconds)
      {:ok, to_token(project, token, entry)}
    end
  end

  defp lookup(project, token) when is_binary(token), do: TokenStore.get(store_key(project, token))
  defp lookup(_project, _token), do: nil

  defp store_key(project, token),
    do: {:temporary_token, project, TokenCrypto.hmac(:temporary_token, to_string(token))}

  defp to_token(project, token, entry) do
    %{
      id: token,
      metadata: %{project: project},
      data:
        Map.merge(entry.opts, %{
          link_member: entry.link_member,
          is_reusable: entry.is_reusable,
          expiration_datetime: entry.expiration_datetime
        })
    }
  end

  defp duration_seconds(nil),
    do: duration_seconds(Application.get_env(:arke_auth, :temporary_token_expiration, 1800))

  defp duration_seconds(seconds) when is_binary(seconds),
    do: seconds |> String.to_integer() |> duration_seconds()

  defp duration_seconds(%{days: days, minutes: minutes}),
    do: duration_seconds(days * 86_400 + minutes * 60)

  defp duration_seconds(%{days: days}), do: duration_seconds(days * 86_400)
  defp duration_seconds(%{minutes: minutes}), do: duration_seconds(minutes * 60)

  defp duration_seconds(seconds) when is_integer(seconds) and seconds > @max_seconds,
    do: Error.create(:auth, "temporary token duration exceeds 30 days")

  defp duration_seconds(seconds) when is_integer(seconds) and seconds > 0, do: {:ok, seconds}

  defp duration_seconds(_duration), do: Error.create(:auth, "invalid temporary token duration")
end
