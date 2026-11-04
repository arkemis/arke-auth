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
  alias Arke.QueryManager
  alias Arke.Boundary.ArkeManager

  @moduledoc """
  Documentation for `Otp`.
  """

  use Arke.System

  arke id: :otp do
  end

  def generate(project, id, action, expiry_datetime \\ get_expiry_datetime()) do
    otp_arke = ArkeManager.get(:otp, :arke_system)
    code = generate_code()
    id = parse_otp_id(action, id)

    case QueryManager.get_by(project: project, arke: otp_arke, id: id, action: action) do
      nil -> nil
      otp -> QueryManager.delete(project, otp)
    end

    expiry_datetime =
      expiry_datetime || NaiveDateTime.utc_now() |> NaiveDateTime.add(300, :second)

    QueryManager.create(project, otp_arke,
      id: id,
      code: code,
      action: action,
      expiry_datetime: expiry_datetime
    )
  end

  def parse_otp_id(action, id), do: "otp_#{action}_#{id}"

  @min_digits 6

  @doc """
  A uniformly random numeric code of `digits` digits (default from
  `config :arke_auth, ArkeAuth.Otp, digits: n`, at least #{@min_digits}), drawn
  from a CSPRNG and returned as a zero-padded string.
  """
  @spec generate_code(pos_integer() | nil) :: String.t()
  def generate_code(digits \\ nil) do
    digits = max(digits || config(:digits, @min_digits), @min_digits)
    space = Integer.pow(10, digits)

    # 64 bits of entropy over a space of at most ~10^19 keeps the modulo bias
    # negligible for any sensible number of digits.
    :crypto.strong_rand_bytes(8)
    |> :binary.decode_unsigned()
    |> rem(space)
    |> Integer.to_string()
    |> String.pad_leading(digits, "0")
  end

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
