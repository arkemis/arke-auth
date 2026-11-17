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

  Counters live in `ArkeAuth.Boundary.TokenStore`, so the limit holds for the
  whole cluster and survives the restart of a single node. They are a floor,
  not a substitute for per-source rate limiting at the HTTP edge.

  Each key carries its own window: the first `hit/2` opens it, later hits
  within the window increment the count, and an expired window starts over.
  """
  alias ArkeAuth.Boundary.TokenStore

  @doc """
  Records one failure for `key` and returns the failure count in the current
  window. `window_seconds` only applies when the hit opens a new window.
  """
  @spec hit(term(), pos_integer()) :: pos_integer()
  def hit(key, window_seconds) when is_integer(window_seconds) and window_seconds > 0,
    do: TokenStore.incr(store_key(key), window_seconds)

  @doc """
  The failure count for `key` in its current window (`0` when none is open).
  """
  @spec count(term()) :: non_neg_integer()
  def count(key), do: TokenStore.get(store_key(key)) || 0

  @doc """
  Closes the window of `key`, forgetting its failures.
  """
  @spec reset(term()) :: :ok
  def reset(key), do: TokenStore.delete(store_key(key))

  # Keeps the counters apart from the other entries of the store.
  defp store_key(key), do: {:attempts, key}
end
