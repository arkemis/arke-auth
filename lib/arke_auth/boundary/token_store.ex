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

defmodule ArkeAuth.Boundary.TokenStore do
  @moduledoc """
  Key/value store with a TTL per entry, shared by every connected node.

  One process per node holds a replica in a `:protected` ETS table. One of
  them is the **owner**, registered with `:global`: every operation is a call
  to the owner, which applies it to its table and then casts it to the
  replicas of the other nodes. Operations are therefore serialized cluster
  wide, and `take/1` consumes an entry at most once.

  When the owner dies, the other nodes elect a new one among themselves; the
  winner already holds a replica. A node that joins (or restarts) loads a
  snapshot from a peer before taking part in the election, so a fresh, empty
  replica never replaces the data of the cluster.

  Expiries are absolute wall-clock seconds (`System.os_time/1`), because they
  travel between nodes and monotonic time is not comparable across nodes.
  Every node sweeps its own expired entries.

  ## Accepted limits

    * Restarting every node at once (or a single-node deploy) loses all
      entries.
    * A write applied by the owner but not yet replicated when the owner dies
      is lost; a `take/1` retried right after such a death may return the same
      value twice.
    * When a netsplit heals, `:global` keeps one of the two owners
      (`:global.random_exit_name/3`) and kills the other; entries written only
      on the losing side are lost.
  """
  use GenServer

  @table :arke_auth_token_store
  @owner {__MODULE__, :owner}
  @sweep_interval :timer.minutes(1)
  @call_attempts 10
  @call_retry_ms 50

  @type key :: term()

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Stores `value` under `key` for `ttl` seconds."
  @spec put(key(), term(), pos_integer()) :: :ok
  def put(key, value, ttl) when is_integer(ttl) and ttl > 0, do: call({:put, key, value, ttl})

  @doc "The value of `key`, or `nil` when it is missing or expired."
  @spec get(key()) :: term() | nil
  def get(key), do: call({:get, key})

  @doc "Reads and deletes `key` in one step: only one caller gets the value."
  @spec take(key()) :: term() | nil
  def take(key), do: call({:take, key})

  @spec delete(key()) :: :ok
  def delete(key), do: call({:delete, key})

  @doc """
  Increments the counter at `key` and returns the new count. A missing or
  expired counter starts at 1 and lives `ttl` seconds; later increments keep
  its expiry (a fixed window).
  """
  @spec incr(key(), pos_integer()) :: pos_integer()
  def incr(key, ttl) when is_integer(ttl) and ttl > 0, do: call({:incr, key, ttl})

  @doc false
  # Empties every replica. Tests only.
  def reset_all(), do: call(:reset_all)

  @doc false
  def table(), do: @table

  # The owner may be missing for a moment while it is being elected.
  defp call(message, attempt \\ 1) do
    GenServer.call({:global, @owner}, message)
  catch
    :exit, reason ->
      if attempt < @call_attempts and retryable?(reason) do
        Process.sleep(@call_retry_ms)
        call(message, attempt + 1)
      else
        exit(reason)
      end
  end

  defp retryable?({:noproc, _}), do: true
  defp retryable?({{:nodedown, _}, _}), do: true
  defp retryable?(_reason), do: false

  # server

  @impl true
  def init(_opts) do
    :ets.new(@table, [:set, :named_table, :protected, read_concurrency: true])
    schedule_sweep()
    {:ok, %{owner_ref: nil}, {:continue, :boot}}
  end

  @impl true
  def handle_continue(:boot, state) do
    load_from_peer(Node.list())
    {:noreply, elect(state)}
  end

  @impl true
  def handle_call({:put, key, value, ttl}, _from, state) do
    write({:insert, {key, value, now() + ttl}})
    {:reply, :ok, state}
  end

  def handle_call({:get, key}, _from, state), do: {:reply, lookup(key), state}

  def handle_call({:take, key}, _from, state) do
    case lookup(key) do
      nil ->
        {:reply, nil, state}

      value ->
        write({:delete, key})
        {:reply, value, state}
    end
  end

  def handle_call({:delete, key}, _from, state) do
    write({:delete, key})
    {:reply, :ok, state}
  end

  def handle_call({:incr, key, ttl}, _from, state) do
    now = now()

    row =
      case :ets.lookup(@table, key) do
        [{^key, count, expires_at}] when is_integer(count) and expires_at > now ->
          {key, count + 1, expires_at}

        _ ->
          {key, 1, now + ttl}
      end

    write({:insert, row})
    {:reply, elem(row, 1), state}
  end

  def handle_call(:reset_all, _from, state) do
    write(:clear)
    {:reply, :ok, state}
  end

  # Answered by the owner and by replicas alike.
  def handle_call(:snapshot, _from, state), do: {:reply, :ets.tab2list(@table), state}

  @impl true
  def handle_cast({:replicate, op}, state) do
    apply_op(op)
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{owner_ref: ref} = state) do
    Process.send_after(self(), :elect, :rand.uniform(100))
    {:noreply, %{state | owner_ref: nil}}
  end

  def handle_info(:elect, state), do: {:noreply, elect(state)}

  def handle_info(:sweep, state) do
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:"=<", :"$1", now()}], [true]}])
    schedule_sweep()
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  # Becomes the owner, or follows the current one and loads its snapshot.
  defp elect(state) do
    case :global.register_name(@owner, self(), &:global.random_exit_name/3) do
      :yes ->
        %{state | owner_ref: nil}

      :no ->
        case :global.whereis_name(@owner) do
          :undefined ->
            Process.send_after(self(), :elect, :rand.uniform(100))
            state

          owner ->
            ref = Process.monitor(owner)
            load_snapshot(owner)
            %{state | owner_ref: ref}
        end
    end
  end

  defp load_from_peer([]), do: :ok

  defp load_from_peer([node | rest]) do
    case load_snapshot({__MODULE__, node}) do
      :ok -> :ok
      :error -> load_from_peer(rest)
    end
  end

  defp load_snapshot(server) do
    rows = GenServer.call(server, :snapshot)
    :ets.delete_all_objects(@table)
    :ets.insert(@table, rows)
    :ok
  catch
    :exit, _reason -> :error
  end

  defp write(op) do
    apply_op(op)
    GenServer.abcast(Node.list(), __MODULE__, {:replicate, op})
  end

  defp apply_op({:insert, row}), do: :ets.insert(@table, row)
  defp apply_op({:delete, key}), do: :ets.delete(@table, key)
  defp apply_op(:clear), do: :ets.delete_all_objects(@table)

  defp lookup(key) do
    now = now()

    case :ets.lookup(@table, key) do
      [{^key, value, expires_at}] when expires_at > now -> value
      _ -> nil
    end
  end

  defp schedule_sweep(), do: Process.send_after(self(), :sweep, @sweep_interval)

  defp now(), do: System.os_time(:second)
end
