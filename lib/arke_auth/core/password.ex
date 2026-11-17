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
  Password hashing with a pepper, bound to the user:

      "pep1$" <> bcrypt(HMAC(pepper, user_id <> <<0>> <> HMAC(pepper, password)))

  The pepper is a secret that never lives in the database, so a bcrypt hash
  written straight into the database (or cracked offline from a dump) is
  useless without it. The user id in the HMAC makes a hash valid only for its
  user: copying the hash of an account whose password one knows onto another
  user does not open that user.

      config :arke_auth, ArkeAuth.Core.Password,
        pepper: System.fetch_env!("ARKE_AUTH_PASSWORD_PEPPER")

  Set it in the application's `runtime.exs`, keep it apart from the token key
  and the Guardian secret, and back it up in a vault: **losing it locks every
  user out**, and changing it invalidates every peppered hash.
  `ArkeAuth.Application` refuses to start without a pepper of at least #{32}
  bytes.

  A user's id exists only once the unit is built, after `before_load`: on
  create `ArkeAuth.Core.User` stores a pending value (`pending/1`, which
  verifies no password) and binds it in `before_create` (`bind_pending/2`).

  Hashes without a prefix are legacy hashes (plain bcrypt). While they are
  accepted, whoever can write the database can set a bcrypt of a password of
  their choice on any user and sign in. To close that:

    1. `mix arke_auth.wrap_legacy_passwords --confirm` turns every legacy hash
       into a wrapped one, `"pepw$" <> salt <> HMAC(pepper, user_id <> <<0>> <>
       legacy_hash)`, without knowing the passwords: the wrapped hash verifies
       the same password, only for its user, and is useless without the pepper;
    2. then `accept_legacy_hashes: false` refuses any legacy hash left or
       written later:

           config :arke_auth, ArkeAuth.Core.Password,
             pepper: System.fetch_env!("ARKE_AUTH_PASSWORD_PEPPER"),
             accept_legacy_hashes: false

  `ArkeAuth.Core.Auth` re-hashes legacy and wrapped hashes with the pepper at
  the next successful sign-in. `mix arke_auth.password_status` counts the
  kinds.
  """
  import Comeonin.Bcrypt, only: [hashpwsalt: 1, checkpw: 2, dummy_checkpw: 0]

  alias ArkeAuth.Utils.TokenCrypto

  @prefix "pep1$"
  @wrap_prefix "pepw$"
  @pending_prefix "pend$"
  # A bcrypt hash: "$2b$" <> cost <> "$" <> 22 chars of salt <> 31 chars of hash.
  @bcrypt ~r/\A\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{53}\z/
  @bcrypt_salt ~r/\A\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{22}\z/
  @min_pepper_bytes 32

  @doc "The peppered hash of `password` for the user `user_id`."
  @spec hash(String.t(), term()) :: String.t()
  def hash(password, user_id) when is_binary(password),
    do: @prefix <> hashpwsalt(bind(user_id, peppered(password)))

  @doc """
  A provisional value for a user that has no id yet. It verifies no password:
  turn it into a hash with `bind_pending/2` once the id is known.
  """
  @spec pending(String.t()) :: String.t()
  def pending(password) when is_binary(password), do: @pending_prefix <> peppered(password)

  @doc "The hash for `user_id` of a value made by `pending/1`; other values unchanged."
  @spec bind_pending(term(), term()) :: term()
  def bind_pending(@pending_prefix <> peppered, user_id),
    do: @prefix <> hashpwsalt(bind(user_id, peppered))

  def bind_pending(hash, _user_id), do: hash

  @doc """
  Checks `password` against the `stored_hash` of the user `user_id`:
  `{:ok, :current}` for a peppered hash, `{:ok, :wrapped}` for a wrapped
  legacy hash, `{:ok, :legacy}` for a plain bcrypt hash while
  `accept_legacy_hashes` is true, `:error` otherwise.
  """
  @spec verify(String.t(), String.t() | nil, term()) ::
          {:ok, :current | :wrapped | :legacy} | :error
  def verify(password, @prefix <> hash, user_id) when is_binary(password),
    do: if(checkpw(bind(user_id, peppered(password)), hash), do: {:ok, :current}, else: :error)

  def verify(password, @wrap_prefix <> <<salt::binary-size(29), digest::binary>>, user_id)
      when is_binary(password) do
    with true <- Regex.match?(@bcrypt_salt, salt),
         legacy = Bcrypt.Base.hash_password(password, salt),
         true <- TokenCrypto.secure_compare(wrap_digest(user_id, legacy), digest) do
      {:ok, :wrapped}
    else
      _ -> :error
    end
  end

  def verify(password, hash, _user_id) when is_binary(password) and is_binary(hash) do
    if accept_legacy?() and legacy?(hash) do
      if checkpw(password, hash), do: {:ok, :legacy}, else: :error
    else
      dummy_verify()
      :error
    end
  end

  def verify(_password, _hash, _user_id) do
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
  Wraps the legacy bcrypt hash of the user `user_id` with the pepper: the
  result verifies the same password for that user only, and cannot be forged
  without the pepper.
  """
  @spec wrap(String.t(), term()) :: {:ok, String.t()} | :error
  def wrap(hash, user_id) do
    if legacy?(hash),
      do: {:ok, @wrap_prefix <> binary_part(hash, 0, 29) <> wrap_digest(user_id, hash)},
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
  defp peppered(password), do: mac(password)

  defp bind(user_id, peppered), do: mac(to_string(user_id) <> <<0>> <> peppered)

  defp wrap_digest(user_id, legacy_hash) do
    validate_config!()

    :crypto.mac(:hmac, :sha256, pepper(), "pepw:" <> to_string(user_id) <> <<0>> <> legacy_hash)
    |> Base.url_encode64(padding: false)
  end

  defp mac(data) do
    validate_config!()
    :crypto.mac(:hmac, :sha256, pepper(), data) |> Base.encode64()
  end

  defp legacy?(hash), do: is_binary(hash) and Regex.match?(@bcrypt, hash)

  defp accept_legacy?(),
    do:
      Application.get_env(:arke_auth, __MODULE__, [])
      |> Keyword.get(:accept_legacy_hashes, true)

  defp pepper(),
    do: Application.get_env(:arke_auth, __MODULE__, []) |> Keyword.get(:pepper)
end
