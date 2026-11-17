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
  @shortdoc "Counts the users by kind of password hash"
  @moduledoc """
  Counts the users of `arke_system` by kind of password hash. Read only.

    * `current`: peppered (`pep1$`);
    * `wrapped`: a legacy hash wrapped with the pepper (`pepw$`), see
      `mix arke_auth.wrap_legacy_passwords`;
    * `legacy`: plain bcrypt, accepted only while `accept_legacy_hashes` is
      true;
    * `invalid`: no usable hash.

  Legacy and wrapped hashes become `current` at the user's next sign-in.

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
  # %{current: n, wrapped: n, legacy: n, invalid: n} over the users of arke_system.
  def count() do
    Arke.QueryManager.filter_by(project: :arke_system, arke_id: :user)
    |> Enum.reduce(%{current: 0, wrapped: 0, legacy: 0, invalid: 0}, fn user, acc ->
      Map.update!(acc, Password.kind(Map.get(user.data, :password_hash)), &(&1 + 1))
    end)
  end

  defp format(counts),
    do: Enum.map_join([:current, :wrapped, :legacy, :invalid], "\n", &"#{&1}: #{counts[&1]}")
end
