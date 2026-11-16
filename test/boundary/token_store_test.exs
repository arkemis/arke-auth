defmodule ArkeAuth.Boundary.TokenStoreTest do
  use ExUnit.Case, async: false

  alias ArkeAuth.Boundary.TokenStore

  setup do
    TokenStore.reset_all()
    :ok
  end

  test "put/3 and get/1" do
    assert :ok = TokenStore.put(:k, %{a: 1}, 60)
    assert TokenStore.get(:k) == %{a: 1}
    assert TokenStore.get(:missing) == nil
  end

  test "an entry expires after its ttl" do
    TokenStore.put(:short, 1, 1)
    Process.sleep(1_100)
    assert TokenStore.get(:short) == nil
  end

  test "take/1 returns the value once" do
    TokenStore.put(:once, "v", 60)
    assert TokenStore.take(:once) == "v"
    assert TokenStore.take(:once) == nil
    assert TokenStore.get(:once) == nil
  end

  test "concurrent take/1 calls consume the value once" do
    TokenStore.put(:race, "v", 60)

    winners =
      1..50
      |> Enum.map(fn _ -> Task.async(fn -> TokenStore.take(:race) end) end)
      |> Enum.map(&Task.await/1)
      |> Enum.reject(&is_nil/1)

    assert winners == ["v"]
  end

  test "delete/1" do
    TokenStore.put(:gone, 1, 60)
    assert :ok = TokenStore.delete(:gone)
    assert TokenStore.get(:gone) == nil
  end

  test "incr/2 counts within a window and restarts after it" do
    assert TokenStore.incr(:counter, 1) == 1
    assert TokenStore.incr(:counter, 1) == 2
    assert TokenStore.incr(:counter, 1) == 3
    Process.sleep(1_100)
    assert TokenStore.incr(:counter, 1) == 1
  end

  test "the sweep removes expired entries from the table" do
    TokenStore.put(:swept, 1, 1)
    Process.sleep(1_100)

    pid = Process.whereis(TokenStore)
    send(pid, :sweep)
    :sys.get_state(pid)

    assert :ets.lookup(TokenStore.table(), :swept) == []
  end
end
