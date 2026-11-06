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

defmodule ArkeAuth.Boundary.AttemptLimiter do
  @moduledoc """
  Fixed-window failure counters used to throttle guessing (OTP codes,
  passwords).

  Counters live in a public ETS table owned by this process, so they are
  **node-local** and reset on restart: in a cluster an attacker gets the limit
  once per node. They are a floor, not a substitute for per-source rate
  limiting at the HTTP edge.

  Each key carries its own window: the first `hit/2` opens it, later hits
  within the window increment the count, and an expired window starts over.
  Expired entries are swept periodically.
  """
  use GenServer

  @table __MODULE__
  @sweep_interval :timer.minutes(1)

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Records one failure for `key` and returns the failure count in the current
  window. `window_seconds` only applies when the hit opens a new window.
  """
  @spec hit(term(), pos_integer()) :: pos_integer()
  def hit(key, window_seconds) when is_integer(window_seconds) and window_seconds > 0 do
    now = now()

    case :ets.lookup(@table, key) do
      [{^key, _count, expires_at}] when expires_at <= now -> :ets.delete(@table, key)
      _ -> :ok
    end

    :ets.update_counter(@table, key, {2, 1}, {key, 0, now + window_seconds})
  end

  @doc """
  The failure count for `key` in its current window (`0` when none is open).
  """
  @spec count(term()) :: non_neg_integer()
  def count(key) do
    now = now()

    case :ets.lookup(@table, key) do
      [{^key, count, expires_at}] when expires_at > now -> count
      _ -> 0
    end
  end

  @doc """
  Closes the window of `key`, forgetting its failures.
  """
  @spec reset(term()) :: :ok
  def reset(key) do
    :ets.delete(@table, key)
    :ok
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:set, :named_table, :public, write_concurrency: true])
    schedule_sweep()
    {:ok, nil}
  end

  @impl true
  def handle_info(:sweep, state) do
    now = now()
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
    schedule_sweep()
    {:noreply, state}
  end

  defp schedule_sweep(), do: Process.send_after(self(), :sweep, @sweep_interval)

  defp now(), do: System.monotonic_time(:second)
end
