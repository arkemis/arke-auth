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

defmodule ArkeAuth.Boundary.OtpManager do
  @moduledoc false
  use Arke.Boundary.UnitManager
  alias ArkeAuth.Core.Otp
  alias ArkeAuth.Boundary.AttemptLimiter
  alias Arke.QueryManager
  alias Arke.Utils.ErrorGenerator, as: Error

  manager_id(:otp)

  def get_code(project, member, action \\ "signin")

  def get_code(project, member, action) when is_atom(action),
    do: get_code(project, member, to_string(action))

  # When OTP_BYPASS_CODE is set, it replaces the member's code for every action
  # in every project. It is a deployment-wide second factor bypass, meant for
  # local development only.
  def get_code(project, member, action) do
    case bypass_code() do
      nil ->
        get_member_code(project, member, action)

      code ->
        %{
          id: Otp.parse_otp_id(action, member.id),
          metadata: %{project: project},
          bypass: true,
          data: %{
            code: code,
            action: action,
            expiry_datetime: NaiveDateTime.utc_now() |> NaiveDateTime.add(300, :second)
          }
        }
    end
  end

  defp bypass_code() do
    case System.get_env("OTP_BYPASS_CODE") do
      nil -> nil
      "" -> nil
      code -> code
    end
  end

  defp get_member_code(project, member, action) do
    QueryManager.get_by(
      project: project,
      arke: "otp",
      id: Otp.parse_otp_id(action, member.id),
      action: action
    )
  end

  @default_max_attempts 5

  @doc """
  Checks `submitted` against the stored `action` code of `member` (a member
  map, or the raw id the code was generated for, e.g. a username at signup).

  A code verifies at most once: it is deleted on success, on expiry, and once
  `config :arke_auth, ArkeAuth.Otp, max_attempts: n` (default
  #{@default_max_attempts}) wrong guesses have been made against it. The
  comparison runs in constant time.

  ## Return
      {:ok, otp_unit}
      {:error, [%{context: "auth", message: "invalid otp"}]}
      {:error, [%{context: "auth", message: "otp expired"}]}
      {:error, [%{context: "auth", message: "too many attempts"}]}
  """
  @spec verify_code(atom(), map() | String.t() | atom(), String.t() | atom(), term()) ::
          {:ok, Arke.Core.Unit.t()} | Arke.Utils.ErrorGenerator.t()
  def verify_code(project, member, action, submitted)

  def verify_code(project, member, action, submitted) when is_atom(action),
    do: verify_code(project, member, to_string(action), submitted)

  def verify_code(project, member, action, submitted) when not is_map(member),
    do: verify_code(project, %{id: member}, action, submitted)

  def verify_code(project, member, action, submitted) do
    case get_code(project, member, action) do
      nil -> Error.create(:auth, "invalid otp")
      otp -> check_code(otp, submitted)
    end
  end

  defp check_code(%{data: %{expiry_datetime: expiry}} = otp, submitted) do
    key = attempts_key(otp)

    cond do
      expired?(expiry) ->
        discard(otp, key)
        Error.create(:auth, "otp expired")

      AttemptLimiter.count(key) >= max_attempts() ->
        delete_otp(otp)
        Error.create(:auth, "too many attempts")

      secure_compare(to_string(otp.data.code), normalize(submitted, otp.data.code)) ->
        discard(otp, key)
        {:ok, otp}

      AttemptLimiter.hit(key, seconds_left(expiry)) >= max_attempts() ->
        delete_otp(otp)
        Error.create(:auth, "too many attempts")

      true ->
        Error.create(:auth, "invalid otp")
    end
  end

  defp discard(otp, key) do
    AttemptLimiter.reset(key)
    delete_otp(otp)
  end

  # The bypass code never changes, so its window is per member and action and
  # is left to expire on its own once locked (not reset), throttling guesses.
  # A real code is deleted once locked; regenerating replaces its value and
  # expiry, so it opens a fresh window. Only a digest of the code is kept.
  defp attempts_key(%{bypass: true, id: id, metadata: %{project: project}}),
    do: {:otp_bypass, project, to_string(id)}

  defp attempts_key(%{id: id, metadata: metadata, data: %{code: code, expiry_datetime: expiry}}),
    do:
      {:otp, Map.get(metadata || %{}, :project), to_string(id),
       :erlang.phash2({to_string(code), expiry})}

  defp expired?(nil), do: true

  defp expired?(expiry),
    do: NaiveDateTime.compare(expiry, NaiveDateTime.utc_now()) != :gt

  defp seconds_left(expiry),
    do: max(NaiveDateTime.diff(expiry, NaiveDateTime.utc_now(), :second), 1)

  defp max_attempts(), do: Otp.config(:max_attempts, @default_max_attempts)

  # JSON clients may send the code as a number, dropping its leading zeros.
  defp normalize(submitted, code) when is_integer(submitted) and submitted >= 0,
    do:
      submitted |> Integer.to_string() |> String.pad_leading(String.length(to_string(code)), "0")

  defp normalize(submitted, _code), do: to_string(submitted)

  # Hashing first gives equal-length inputs, so neither the content nor the
  # length of the stored code leaks through timing.
  defp secure_compare(left, right) do
    diff = :crypto.exor(:crypto.hash(:sha256, left), :crypto.hash(:sha256, right))
    :binary.decode_unsigned(diff) == 0
  end

  def delete_otp(%Arke.Core.Unit{metadata: %{project: project}} = unit),
    do: QueryManager.delete(project, unit)

  def delete_otp(_unit), do: nil
end
