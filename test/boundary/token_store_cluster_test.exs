defmodule ArkeAuth.Boundary.TokenStoreClusterTest do
  use ExUnit.Case, async: false

  alias ArkeAuth.Boundary.TokenStore

  @moduletag :cluster
  @owner {TokenStore, :owner}

  setup_all do
    unless Node.alive?() do
      {_, 0} = System.cmd("epmd", ["-daemon"])
      {:ok, _} = Node.start(:"primary@127.0.0.1", :longnames)
    end

    :ok
  end

  setup do
    TokenStore.reset_all()
    on_exit(fn -> ensure_owner() end)
    :ok
  end

  test "an entry written on one node is read from another" do
    [peer] = start_peers(1)
    TokenStore.put(:shared, "v", 60)

    assert :erpc.call(peer, TokenStore, :get, [:shared]) == "v"
  end

  test "incr/2 from different nodes updates one counter" do
    [peer] = start_peers(1)

    assert TokenStore.incr(:cluster_counter, 60) == 1
    assert :erpc.call(peer, TokenStore, :incr, [:cluster_counter, 60]) == 2
  end

  test "concurrent take/1 from two nodes consumes the value once" do
    [peer] = start_peers(1)
    TokenStore.put(:cluster_race, "v", 60)

    local = Task.async(fn -> TokenStore.take(:cluster_race) end)
    remote = Task.async(fn -> :erpc.call(peer, TokenStore, :take, [:cluster_race]) end)

    assert Enum.reject([Task.await(local), Task.await(remote)], &is_nil/1) == ["v"]
  end

  test "a node started after the writes loads them at boot" do
    TokenStore.put(:before_boot, "v", 60)
    [peer] = start_peers(1)

    rows = :erpc.call(peer, :ets, :tab2list, [TokenStore.table()])
    assert Enum.any?(rows, &match?({:before_boot, "v", _}, &1))
  end

  test "when the owner dies another node takes over with the data" do
    [peer_a, _peer_b] = start_peers(2)
    TokenStore.put(:survivor, "v", 60)

    owner = :global.whereis_name(@owner)
    assert node(owner) == node()

    # Stop the primary's store under its supervisor so it cannot win the
    # election back before the peers do.
    :ok = Supervisor.terminate_child(ArkeAuth.Supervisor, TokenStore)

    new_owner = wait_for_owner(fn pid -> pid != owner end)
    assert node(new_owner) != node()
    assert :erpc.call(peer_a, TokenStore, :get, [:survivor]) == "v"
  end

  defp start_peers(count) do
    for _ <- 1..count do
      # Not linked: a peer linked to the test process would already be
      # shutting down when on_exit runs.
      {:ok, peer_pid, peer} =
        :peer.start(%{
          name: :peer.random_name(),
          host: ~c"127.0.0.1",
          longnames: true,
          args: [~c"-setcookie", Atom.to_charlist(Node.get_cookie())]
        })

      :ok = :erpc.call(peer, :code, :add_paths, [:code.get_path()])
      {:ok, _} = :erpc.call(peer, Application, :ensure_all_started, [:elixir])
      :ok = :erpc.call(peer, :global, :sync, [])
      {:ok, _} = :erpc.call(peer, GenServer, :start, [TokenStore, [], [name: TokenStore]])
      # Waits for handle_continue(:boot): the snapshot and the election.
      _ = :erpc.call(peer, :sys, :get_state, [TokenStore])

      on_exit(fn -> :peer.stop(peer_pid) end)
      peer
    end
  end

  defp wait_for_owner(accept?, attempts \\ 50) do
    case :global.whereis_name(@owner) do
      pid when is_pid(pid) ->
        if accept?.(pid), do: pid, else: retry_owner(accept?, attempts)

      :undefined ->
        retry_owner(accept?, attempts)
    end
  end

  defp retry_owner(_accept?, 0), do: flunk("no new TokenStore owner was elected")

  defp retry_owner(accept?, attempts) do
    Process.sleep(50)
    wait_for_owner(accept?, attempts - 1)
  end

  # Leaves the primary's store running for the next tests.
  defp ensure_owner() do
    case Supervisor.restart_child(ArkeAuth.Supervisor, TokenStore) do
      {:ok, _} -> :ok
      {:error, :running} -> :ok
      {:error, {:already_started, _}} -> :ok
    end

    wait_for_owner(fn pid -> node(pid) == node() end)
  end
end
