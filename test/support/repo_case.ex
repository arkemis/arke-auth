defmodule ArkeAuth.RepoCase do
  @moduledoc """
  Case template for suites that run against the in-memory managers.

  Cases using it are synchronous and must stay that way: `on_exit` calls
  `Arke.Test.Sandbox.restore/0`, which runs `:ets.delete_all_objects` on the
  global manager tables. An `async: true` test that reads `ArkeManager` or
  `QueryManager` can be wiped mid-run by a sync case tearing down.
  `test/core/password_hash_test.exs` is async only because it touches plain
  maps and never reads a manager.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      alias Arke.Boundary.ArkeManager
      alias Arke.QueryManager
      alias Arke.Core.Unit
      alias ArkeAuth.Core.{Auth, User}
    end
  end

  setup do
    on_exit(&Arke.Test.Sandbox.restore/0)
    :ok
  end
end
