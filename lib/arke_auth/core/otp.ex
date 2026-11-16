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

defmodule ArkeAuth.Core.Otp do
  @moduledoc """
  One-time codes for signup, signin and password reset.

  A code lives only in `ArkeAuth.Boundary.TokenStore`, which keeps an HMAC of
  it (`ArkeAuth.Utils.TokenCrypto`), never the code itself: the clear code is
  returned once, to the caller that mails or texts it. A new code for the same
  project, action and subject replaces the previous one and resets its
  attempt count. Verification is `ArkeAuth.Boundary.OtpManager.verify_code/4`.

      config :arke_auth, ArkeAuth.Otp,
        digits: 4,              # 4 or 6
        ttl: {5, :minutes},
        max_attempts: 5,
        resend_cooldown_seconds: 30   # 0 disables it
  """
  use Arke.System

  alias ArkeAuth.Boundary.{AttemptLimiter, TokenStore}
  alias ArkeAuth.Utils.TokenCrypto
  alias Arke.Utils.ErrorGenerator, as: Error

  # The `otp` arke stays in the registry until the legacy data is removed;
  # codes are no longer stored as units.
  arke id: :otp do
  end

  @allowed_digits [4, 6]
  @default_resend_cooldown 30
  @default_digits 4

  # An expired code stays in the store this long, so that verifying it answers
  # "otp expired" rather than "invalid otp".
  @expired_grace_seconds 300

  @doc """
  Generates a code for `subject` (a member id, or the username at signup),
  stores its HMAC and returns it in clear, once.
  """
  def generate(project, subject, action, expiry_datetime \\ get_expiry_datetime()) do
    if resend_allowed?(project, action, subject),
      do: put_code(project, subject, action, generate_code(), expiry_datetime),
      else: Error.create(:auth, "otp resend too soon")
  end

  # At most one code per `resend_cooldown_seconds` for the same project,
  # action and subject. `incr/2` runs on the store owner, so two concurrent
  # requests cannot both pass.
  defp resend_allowed?(project, action, subject) do
    case resend_cooldown() do
      0 ->
        true

      cooldown ->
        key = {:otp_cooldown, project, to_string(action), to_string(subject)}
        TokenStore.incr(key, cooldown) == 1
    end
  end

  defp resend_cooldown(), do: config(:resend_cooldown_seconds, @default_resend_cooldown)

  @doc false
  # Stores a chosen code. Used by generate/4 and by tests.
  def put_code(project, subject, action, code, expiry_datetime) do
    action = to_string(action)
    subject = to_string(subject)
    code = to_string(code)

    expiry_datetime =
      expiry_datetime || NaiveDateTime.utc_now() |> NaiveDateTime.add(300, :second)

    entry = %{
      code_hmac: code_hmac(project, action, subject, code),
      digits: String.length(code),
      expiry_datetime: expiry_datetime
    }

    ttl = max(NaiveDateTime.diff(expiry_datetime, NaiveDateTime.utc_now()), 0)
    :ok = TokenStore.put(store_key(project, action, subject), entry, ttl + @expired_grace_seconds)
    AttemptLimiter.reset(attempt_key(project, action, subject))

    {:ok, to_otp(project, action, subject, entry, code)}
  end

  def parse_otp_id(action, id), do: "otp_#{action}_#{id}"

  @doc false
  def store_key(project, action, subject),
    do: {:otp, project, to_string(action), to_string(subject)}

  @doc false
  def attempt_key(project, action, subject),
    do: {:otp, project, to_string(action), to_string(subject)}

  @doc false
  def code_hmac(project, action, subject, code),
    do:
      TokenCrypto.hmac(:otp, [
        to_string(project),
        0,
        to_string(action),
        0,
        to_string(subject),
        0,
        to_string(code)
      ])

  @doc false
  # The map handed to callers and mailers. `code` is present only right after
  # generation.
  def to_otp(project, action, subject, entry, code \\ nil) do
    data = %{action: action, expiry_datetime: entry.expiry_datetime}

    %{
      id: parse_otp_id(action, subject),
      metadata: %{project: project, subject: subject},
      data: if(code, do: Map.put(data, :code, code), else: data)
    }
  end

  @doc """
  A uniformly random numeric code of `digits` digits (default from
  `config :arke_auth, ArkeAuth.Otp, digits: n`, #{@default_digits} when unset),
  drawn from a CSPRNG and returned as a zero-padded string. Only 4 or 6
  digits are allowed.
  """
  @spec generate_code(pos_integer() | nil) :: String.t()
  def generate_code(digits \\ nil) do
    digits = check_digits!(digits || config(:digits, @default_digits))
    space = Integer.pow(10, digits)

    # 64 bits of entropy over a space of at most 10^6 keeps the modulo bias
    # negligible.
    :crypto.strong_rand_bytes(8)
    |> :binary.decode_unsigned()
    |> rem(space)
    |> Integer.to_string()
    |> String.pad_leading(digits, "0")
  end

  @doc """
  Raises unless the configured `digits` is 4 or 6 and
  `resend_cooldown_seconds` is a non-negative integer. Called when
  `ArkeAuth.Application` starts.
  """
  @spec validate_config!() :: :ok
  def validate_config!() do
    check_digits!(config(:digits, @default_digits))

    unless is_integer(resend_cooldown()) and resend_cooldown() >= 0,
      do:
        raise(
          ArgumentError,
          "config :arke_auth, ArkeAuth.Otp, resend_cooldown_seconds: must be an integer >= 0"
        )

    :ok
  end

  defp check_digits!(digits) when digits in @allowed_digits, do: digits

  defp check_digits!(digits),
    do:
      raise(
        ArgumentError,
        "config :arke_auth, ArkeAuth.Otp, digits: must be 4 or 6, got: #{inspect(digits)}"
      )

  @doc false
  def config(key, default),
    do: Keyword.get(Application.get_env(:arke_auth, ArkeAuth.Otp, []), key, default)

  defp get_expiry_datetime() do
    {value, unit} = config(:ttl, nil) || {5, :minutes}
    seconds = convert_to_seconds(value, unit)
    NaiveDateTime.utc_now() |> NaiveDateTime.add(seconds, :second)
  end

  defp convert_to_seconds(value, :seconds), do: value
  defp convert_to_seconds(value, :minutes), do: value * 60
  defp convert_to_seconds(value, :days), do: value * 24 * 60 * 60
end
