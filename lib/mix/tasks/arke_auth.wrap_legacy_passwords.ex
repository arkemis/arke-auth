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

defmodule Mix.Tasks.ArkeAuth.WrapLegacyPasswords do
  @shortdoc "Wraps the legacy password hashes with the pepper"
  @moduledoc """
  Turns every legacy (plain bcrypt) password hash of `arke_system` into a
  wrapped one, `"pepw$" <> salt <> HMAC(pepper, legacy_hash)`. Users keep
  their password and notice nothing; the hash in the database becomes useless
  without the pepper.

  Without `--confirm` it only prints the counts. With `--confirm` it writes
  the wrapped hashes. It can run again: hashes already wrapped or peppered
  are left alone.

      $ mix arke_auth.wrap_legacy_passwords
      $ mix arke_auth.wrap_legacy_passwords --confirm

  **Back up the database and the pepper first**: a wrapped hash cannot be
  turned back into the legacy one, and without the pepper it verifies no
  password. Then set `accept_legacy_hashes: false` (see
  `ArkeAuth.Core.Password`) so that a legacy hash written into the database
  later is refused.
  """
  use Mix.Task

  alias ArkeAuth.Core.Password

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: [confirm: :boolean])
    confirm = Keyword.get(opts, :confirm, false)
    Mix.Task.run("app.start")

    Mix.shell().info(
      "WARNING: wrapping is irreversible. Back up the database and the pepper first." <>
        if(confirm, do: "", else: "\nDry run: nothing is changed without --confirm.")
    )

    %{legacy: legacy, wrapped: wrapped} = wrap(confirm)
    Mix.shell().info("legacy: #{legacy}\nwrapped: #{wrapped}")
  end

  @doc false
  # Counts the legacy hashes and, with `confirm`, wraps them.
  def wrap(confirm) do
    legacy =
      Arke.QueryManager.filter_by(project: :arke_system, arke_id: :user)
      |> Enum.filter(&(Password.kind(Map.get(&1.data, :password_hash)) == :legacy))

    wrapped = if confirm, do: Enum.count(legacy, &wrap_user/1), else: 0
    %{legacy: length(legacy), wrapped: wrapped}
  end

  # User.before_update/3 refuses a password_hash set directly, so the wrapped
  # hash goes through the configured persistence.
  defp wrap_user(%{data: data} = user) do
    {:ok, hash} = Password.wrap(data.password_hash)
    update = Application.get_env(:arke, :persistence)[:arke_postgres][:update]

    case update.(:arke_system, %{user | data: Map.put(data, :password_hash, hash)}) do
      {:ok, _} -> true
      _ -> false
    end
  end
end
