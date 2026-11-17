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

defmodule ArkeAuth.Utils.TokenCrypto do
  @moduledoc """
  Random tokens, keyed digests, signatures and constant-time comparison for
  the secrets arke_auth hands out (OTP codes, magic links, reset links).

  The key never lives in the database, so reading or writing the database is
  not enough to recover or forge a token:

      config :arke_auth, ArkeAuth.Utils.TokenCrypto,
        token_key: System.fetch_env!("ARKE_AUTH_TOKEN_KEY"),
        previous_keys: []

  Set it in the application's `runtime.exs`, from the environment or a secret
  manager. `token_key` must be at least #{32} bytes; `ArkeAuth.Application`
  refuses to start without it. Keep it apart from the Guardian secret and from
  the password pepper (`ArkeAuth.Core.Password`).

  Rotation: sign with the new key and move the old one to `previous_keys`;
  signatures made with a previous key still verify. Digests used as lookup
  keys (`hmac/2`) are computed with the current key only, so rotating it
  invalidates the short-lived entries looked up by digest.
  """

  @min_key_bytes 32

  @doc "A url-safe random token of `bytes` random bytes."
  @spec random_token(pos_integer()) :: String.t()
  def random_token(bytes \\ 32),
    do: :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)

  @doc """
  HMAC-SHA256 of `data` with the current key. `purpose` separates the uses:
  the same data gives different digests for different purposes.
  """
  @spec hmac(atom(), iodata()) :: binary()
  def hmac(purpose, data) when is_atom(purpose), do: mac(token_key(), purpose, data)

  @doc "`payload` and its signature, url-safe, joined by a dot."
  @spec sign(atom(), binary()) :: String.t()
  def sign(purpose, payload) when is_atom(purpose) and is_binary(payload),
    do: encode(payload) <> "." <> encode(hmac(purpose, payload))

  @doc "The payload of a token made by `sign/2` for the same `purpose`."
  @spec verify(atom(), term()) :: {:ok, binary()} | :error
  def verify(purpose, token) when is_atom(purpose) and is_binary(token) do
    with [payload64, signature64] <- String.split(token, "."),
         {:ok, payload} <- decode(payload64),
         {:ok, signature} <- decode(signature64),
         true <-
           Enum.any?(keys(), &secure_compare(mac(&1, purpose, payload), signature)) do
      {:ok, payload}
    else
      _ -> :error
    end
  end

  def verify(_purpose, _token), do: :error

  @doc "Compares two binaries in constant time for a given length."
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(left, right) when is_binary(left) and is_binary(right),
    do: byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)

  def secure_compare(_left, _right), do: false

  @doc """
  Raises unless a `token_key` of at least #{@min_key_bytes} bytes is
  configured. Called when `ArkeAuth.Application` starts.
  """
  @spec validate_config!() :: :ok
  def validate_config!() do
    case config(:token_key) do
      key when is_binary(key) and byte_size(key) >= @min_key_bytes ->
        :ok

      _ ->
        raise ArgumentError,
              "config :arke_auth, #{inspect(__MODULE__)}, token_key: must be a string of " <>
                "at least #{@min_key_bytes} bytes (read it from the environment in runtime.exs)"
    end
  end

  defp mac(key, purpose, data),
    do: :crypto.mac(:hmac, :sha256, key, [Atom.to_string(purpose), 0, data])

  defp keys(), do: [token_key() | List.wrap(config(:previous_keys))]

  defp token_key() do
    validate_config!()
    config(:token_key)
  end

  defp config(key), do: Keyword.get(Application.get_env(:arke_auth, __MODULE__, []), key)

  defp encode(binary), do: Base.url_encode64(binary, padding: false)

  defp decode(string), do: Base.url_decode64(string, padding: false)
end
