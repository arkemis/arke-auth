defmodule ArkeAuth.ResetPasswordToken do
  @moduledoc """
  Signed, stateless password reset tokens.

  A token carries the user id, its expiry and a fingerprint of the current
  password hash, signed with `ArkeAuth.Utils.TokenCrypto`. Nothing is stored:
  the signature proves it was issued by the server, and the fingerprint makes
  it single-use, because changing the password changes the hash and voids
  every token issued before. The fingerprint is a keyed digest, never the hash
  itself: the token is signed, not encrypted, and travels by mail.

      config :arke_auth, :reset_password_token_ttl, weeks: 2

  The ttl accepts `weeks`, `days`, `hours`, `minutes` and `seconds`, and may
  not exceed 2 weeks; `ArkeAuth.Application` refuses to start otherwise.
  """
  alias Arke.QueryManager
  alias ArkeAuth.Utils.TokenCrypto
  alias Arke.Utils.ErrorGenerator, as: Error

  @max_seconds 14 * 86_400
  @units [weeks: 7 * 86_400, days: 86_400, hours: 3_600, minutes: 60, seconds: 1]

  @doc """
  A token for `user` and its data (`token`, `expiration`, `user_id`).
  """
  @spec issue(Arke.Core.Unit.t()) :: {:ok, map()}
  def issue(%{id: user_id, data: data}) do
    expiration = DateTime.utc_now() |> DateTime.add(ttl_seconds(), :second)

    payload =
      Enum.join(
        [to_string(user_id), DateTime.to_unix(expiration), fingerprint(data.password_hash)],
        "|"
      )

    {:ok,
     %{
       token: TokenCrypto.sign(:reset_password, payload),
       expiration: expiration,
       user_id: to_string(user_id)
     }}
  end

  @doc """
  The user of a valid token: the signature verifies, it has not expired and
  the password has not changed since it was issued.
  """
  @spec verify(term()) :: {:ok, Arke.Core.Unit.t()} | Arke.Utils.ErrorGenerator.t()
  def verify(token) do
    with {:ok, payload} <- TokenCrypto.verify(:reset_password, token),
         [user_id, expires_at, print] <- String.split(payload, "|"),
         {expires_at, ""} <- Integer.parse(expires_at),
         true <- expires_at > DateTime.to_unix(DateTime.utc_now()),
         %Arke.Core.Unit{} = user <-
           QueryManager.get_by(id: user_id, arke_id: :user, project: :arke_system),
         true <- TokenCrypto.secure_compare(fingerprint(user.data.password_hash), print) do
      {:ok, user}
    else
      _ -> Error.create(:auth, "invalid token")
    end
  end

  @doc "The configured ttl, in seconds."
  @spec ttl_seconds() :: pos_integer()
  def ttl_seconds() do
    ttl = Application.get_env(:arke_auth, :reset_password_token_ttl, weeks: 2)

    Enum.reduce(ttl, 0, fn {unit, value}, acc ->
      acc + value * Keyword.fetch!(@units, unit)
    end)
  end

  @doc """
  Raises unless `:reset_password_token_ttl` is positive and at most 2 weeks.
  Called when `ArkeAuth.Application` starts.
  """
  @spec validate_config!() :: :ok
  def validate_config!() do
    case ttl_seconds() do
      seconds when seconds > 0 and seconds <= @max_seconds ->
        :ok

      seconds ->
        raise ArgumentError,
              "config :arke_auth, :reset_password_token_ttl must be positive and at most " <>
                "2 weeks, got #{seconds} seconds"
    end
  rescue
    error in [KeyError, ArithmeticError, Protocol.UndefinedError, FunctionClauseError] ->
      reraise ArgumentError,
              "config :arke_auth, :reset_password_token_ttl must be a keyword list of " <>
                "weeks, days, hours, minutes or seconds: #{Exception.message(error)}",
              __STACKTRACE__
  end

  defp fingerprint(password_hash),
    do:
      TokenCrypto.hmac(:reset_password_fp, to_string(password_hash))
      |> binary_part(0, 16)
      |> Base.url_encode64(padding: false)
end
