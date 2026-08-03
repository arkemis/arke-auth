defmodule ArkeAuth.RepoCase do
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
