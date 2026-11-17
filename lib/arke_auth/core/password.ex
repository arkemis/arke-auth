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

  Hashes without a prefix are legacy hashes (plain bcrypt). While they are
  accepted, whoever can write the database can set a bcrypt of a password of
  their choice on any user and sign in. To close that:

    1. `mix arke_auth.wrap_legacy_passwords --confirm` turns every legacy hash
       into a wrapped one, `"pepw$" <> salt <> HMAC(pepper, legacy_hash)`,
       without knowing the passwords: the wrapped hash verifies the same
       password and is useless without the pepper;
    2. then `accept_legacy_hashes: false` refuses any legacy hash left or
       written later:

           config :arke_auth, ArkeAuth.Core.Password,
             pepper: System.fetch_env!("ARKE_AUTH_PASSWORD_PEPPER"),
             accept_legacy_hashes: false

  `ArkeAuth.Core.Auth` re-hashes legacy and wrapped hashes with the pepper at
  the next successful sign-in. `mix arke_auth.password_status` counts the
  three kinds.
  """
  import Comeonin.Bcrypt, only: [hashpwsalt: 1, checkpw: 2, dummy_checkpw: 0]

  @prefix "pep1$"
  @wrap_prefix "pepw$"
  # A bcrypt hash: "$2b$" <> cost <> "$" <> 22 chars of salt <> 31 chars of hash.
  @bcrypt ~r/\A\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{53}\z/
  @bcrypt_salt ~r/\A\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{22}\z/
  @min_pepper_bytes 32

  @doc "The peppered hash of `password`."
  @spec hash(String.t()) :: String.t()
  def hash(password) when is_binary(password), do: @prefix <> hashpwsalt(peppered(password))

  @doc """
  Checks `password` against `stored_hash`: `{:ok, :current}` for a peppered
  hash, `{:ok, :wrapped}` for a wrapped legacy hash, `{:ok, :legacy}` for a
  plain bcrypt hash while `accept_legacy_hashes` is true, `:error` otherwise.
  """
  @spec verify(String.t(), String.t() | nil) :: {:ok, :current | :wrapped | :legacy} | :error
  def verify(password, @prefix <> hash) when is_binary(password),
    do: if(checkpw(peppered(password), hash), do: {:ok, :current}, else: :error)

  def verify(password, @wrap_prefix <> <<salt::binary-size(29), digest::binary>>)
      when is_binary(password) do
    with true <- Regex.match?(@bcrypt_salt, salt),
         legacy = Bcrypt.Base.hash_password(password, salt),
         true <- ArkeAuth.Utils.TokenCrypto.secure_compare(wrap_digest(legacy), digest) do
      {:ok, :wrapped}
    else
      _ -> :error
    end
  end

  def verify(password, hash) when is_binary(password) and is_binary(hash) do
    if accept_legacy?() and legacy?(hash) do
      if checkpw(password, hash), do: {:ok, :legacy}, else: :error
    else
      dummy_verify()
      :error
    end
  end

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

  @doc "The kind of a stored hash: `:current`, `:wrapped`, `:legacy` or `:invalid`."
  @spec kind(term()) :: :current | :wrapped | :legacy | :invalid
  def kind(@prefix <> _hash), do: :current
  def kind(@wrap_prefix <> _hash), do: :wrapped
  def kind(hash), do: if(legacy?(hash), do: :legacy, else: :invalid)

  @doc """
  Wraps a legacy bcrypt hash with the pepper: the result verifies the same
  password, and cannot be forged without the pepper.
  """
  @spec wrap(String.t()) :: {:ok, String.t()} | :error
  def wrap(hash) do
    if legacy?(hash),
      do: {:ok, @wrap_prefix <> binary_part(hash, 0, 29) <> wrap_digest(hash)},
      else: :error
  end

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

  defp legacy?(hash), do: is_binary(hash) and Regex.match?(@bcrypt, hash)

  defp wrap_digest(legacy_hash) do
    validate_config!()

    :crypto.mac(:hmac, :sha256, pepper(), "pepw:" <> legacy_hash)
    |> Base.url_encode64(padding: false)
  end

  defp accept_legacy?(),
    do:
      Application.get_env(:arke_auth, __MODULE__, [])
      |> Keyword.get(:accept_legacy_hashes, true)

  defp pepper(),
    do: Application.get_env(:arke_auth, __MODULE__, []) |> Keyword.get(:pepper)
end
