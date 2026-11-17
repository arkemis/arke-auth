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

defmodule Mix.Tasks.ArkeAuth.PurgeLegacyAuthData do
  @shortdoc "Counts, and with --confirm deletes, the auth data left in the database"
  @moduledoc """
  Since the auth hardening release, OTP codes, temporary tokens, member
  tokens and reset links no longer live in the database, and the rows left
  there no longer give access. This task finds them:

    * units of the `otp` and `temporary_token` arkes in each project;
    * units of the `reset_password_token` arke in `arke_system`;
    * members whose `auth_token` field still holds a value.

  Without `--confirm` it only prints the counts. With `--confirm` it deletes
  the units and clears the `auth_token` fields.

  **Irreversible: back up the database first.** Run it only once every node
  runs the hardening release.

      $ mix arke_auth.purge_legacy_auth_data --project my_project
      $ mix arke_auth.purge_legacy_auth_data --all
      $ mix arke_auth.purge_legacy_auth_data --all --confirm

  `--all` covers `arke_system` and every project listed in it.
  """
  use Mix.Task

  alias Arke.QueryManager

  @legacy_arkes [:otp, :temporary_token]

  @impl Mix.Task
  def run(args) do
    {opts, _rest} =
      OptionParser.parse!(args, strict: [project: :keep, all: :boolean, confirm: :boolean])

    projects = projects(opts)

    if projects == [] do
      Mix.Tasks.Help.run(["arke_auth.purge_legacy_auth_data"])
    else
      Mix.Task.run("app.start")
      confirm = Keyword.get(opts, :confirm, false)

      Mix.shell().info(
        "WARNING: deleting legacy auth data is irreversible. Back up the database first." <>
          if(confirm, do: "", else: "\nDry run: nothing is changed without --confirm.")
      )

      projects
      |> purge(confirm)
      |> Enum.each(fn {project, counts} -> Mix.shell().info(format(project, counts, confirm)) end)
    end
  end

  @doc false
  # Returns %{project => %{otp: n, temporary_token: n, reset_password_token: n,
  # member_auth_token: n}}; deletes and clears only when `confirm` is true.
  def purge(projects, confirm) do
    Map.new(projects, fn project -> {project, purge_project(project, confirm)} end)
  end

  defp purge_project(project, confirm) do
    arkes =
      if project == :arke_system, do: [:reset_password_token | @legacy_arkes], else: @legacy_arkes

    unit_counts =
      Map.new(arkes, fn arke_id ->
        units = QueryManager.filter_by(project: project, arke_id: arke_id)
        if confirm, do: Enum.each(units, &delete_unit(project, &1))
        {arke_id, length(units)}
      end)

    members =
      QueryManager.filter_by(project: project, group_id: "arke_auth_member")
      |> Enum.filter(&(Map.get(&1.data, :auth_token) not in [nil, ""]))

    if confirm, do: Enum.each(members, &QueryManager.update(&1, auth_token: nil))

    unit_counts
    |> Map.put_new(:reset_password_token, 0)
    |> Map.put(:member_auth_token, length(members))
  end

  # The legacy arkes have no module and no hooks any more: delete through the
  # configured persistence directly.
  defp delete_unit(project, unit) do
    delete = Application.get_env(:arke, :persistence)[:arke_postgres][:delete]
    {:ok, nil} = delete.(project, unit)
  end

  defp projects(opts) do
    named = opts |> Keyword.get_values(:project) |> Enum.map(&String.to_atom/1)

    if Keyword.get(opts, :all, false) do
      Mix.Task.run("app.start")

      listed =
        QueryManager.filter_by(project: :arke_system, arke: :arke_project)
        |> Enum.map(&String.to_atom(to_string(&1.id)))

      Enum.uniq([:arke_system | listed] ++ named)
    else
      named
    end
  end

  defp format(project, counts, confirm) do
    verb = if confirm, do: "removed", else: "found"

    "#{project}: #{verb} otp=#{counts.otp} temporary_token=#{counts.temporary_token} " <>
      "reset_password_token=#{counts.reset_password_token} " <>
      "member auth_token=#{counts.member_auth_token}"
  end
end
