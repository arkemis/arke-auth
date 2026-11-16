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

defmodule ArkeAuth.Core.Password do
  @moduledoc """
  Password hashing with a pepper: `"pep1$" <> bcrypt(HMAC(pepper, password))`.

  The pepper is a secret that never lives in the database, so a bcrypt hash
  written straight into the database (or cracked offline from a dump) is
  useless without it:

      config :arke_auth, ArkeAuth.Core.Password,
        pepper: System.fetch_env!("ARKE_AUTH_PASSWORD_PEPPER")

  Set it in the application's `runtime.exs`, keep it apart from the token key
  and the Guardian secret, and back it up in a vault: **losing it locks every
  user out**, and changing it invalidates every peppered hash.
  `ArkeAuth.Application` refuses to start without a pepper of at least #{32}
  bytes.

  Hashes without the `pep1$` prefix are legacy hashes: they still verify, and
  `ArkeAuth.Core.Auth` re-hashes them with the pepper at the next successful
  sign-in. `mix arke_auth.password_status` counts both kinds.
  """
  import Comeonin.Bcrypt, only: [hashpwsalt: 1, checkpw: 2, dummy_checkpw: 0]

  @prefix "pep1$"
  @min_pepper_bytes 32

  @doc "The peppered hash of `password`."
  @spec hash(String.t()) :: String.t()
  def hash(password) when is_binary(password), do: @prefix <> hashpwsalt(peppered(password))

  @doc """
  Checks `password` against `stored_hash`: `{:ok, :current}` for a peppered
  hash, `{:ok, :legacy}` for a hash without the prefix, `:error` otherwise.
  """
  @spec verify(String.t(), String.t() | nil) :: {:ok, :current | :legacy} | :error
  def verify(password, @prefix <> hash) when is_binary(password),
    do: if(checkpw(peppered(password), hash), do: {:ok, :current}, else: :error)

  def verify(password, hash) when is_binary(password) and is_binary(hash),
    do: if(checkpw(password, hash), do: {:ok, :legacy}, else: :error)

  def verify(_password, _hash) do
    dummy_verify()
    :error
  end

  @doc "Spends the time of a check, so that a missing user is not told apart."
  def dummy_verify(), do: dummy_checkpw()

  @doc "Whether `hash` is peppered."
  @spec current?(term()) :: boolean()
  def current?(@prefix <> _hash), do: true
  def current?(_hash), do: false

  @doc """
  Raises unless a pepper of at least #{@min_pepper_bytes} bytes is configured.
  Called when `ArkeAuth.Application` starts.
  """
  @spec validate_config!() :: :ok
  def validate_config!() do
    case pepper() do
      pepper when is_binary(pepper) and byte_size(pepper) >= @min_pepper_bytes ->
        :ok

      _ ->
        raise ArgumentError,
              "config :arke_auth, #{inspect(__MODULE__)}, pepper: must be a string of at " <>
                "least #{@min_pepper_bytes} bytes (read it from the environment in runtime.exs)"
    end
  end

  # A fixed-length input also avoids bcrypt truncating passwords at 72 bytes.
  defp peppered(password) do
    validate_config!()
    :crypto.mac(:hmac, :sha256, pepper(), password) |> Base.encode64()
  end

  defp pepper(),
    do: Application.get_env(:arke_auth, __MODULE__, []) |> Keyword.get(:pepper)
end
