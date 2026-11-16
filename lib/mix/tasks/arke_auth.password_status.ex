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

defmodule Mix.Tasks.ArkeAuth.PasswordStatus do
  @shortdoc "Counts the users whose password hash is peppered or legacy"
  @moduledoc """
  Counts the users of `arke_system` whose password hash already carries the
  pepper (`pep1$`) and those still on a legacy hash, which is re-hashed at
  their next sign-in. Read only.

      $ mix arke_auth.password_status
  """
  use Mix.Task

  alias ArkeAuth.Core.Password

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")
    Mix.shell().info(format(count()))
  end

  @doc false
  # %{peppered: n, legacy: n} over the users of arke_system.
  def count() do
    Arke.QueryManager.filter_by(project: :arke_system, arke_id: :user)
    |> Enum.reduce(%{peppered: 0, legacy: 0}, fn user, acc ->
      key = if Password.current?(Map.get(user.data, :password_hash)), do: :peppered, else: :legacy
      Map.update!(acc, key, &(&1 + 1))
    end)
  end

  defp format(%{peppered: peppered, legacy: legacy}),
    do: "peppered: #{peppered}\nlegacy: #{legacy}"
end
