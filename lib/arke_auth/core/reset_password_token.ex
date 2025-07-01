defmodule ArkeAuth.ResetPasswordToken do
  @moduledoc """
  Documentation for `ResetPasswordToken`.
  """

  use Arke.System

  arke do
  end

  def before_load(data, :create) do
    # IF map has arke_id means it has been retrieved from db (delete if expiration is past by ??)
    case Map.get(data, :arke_id) do
      nil ->
        create_token(data)

      _ ->
        {:ok, data}
    end
  end

  def before_load(data, _persistence_fn), do: {:ok, data}

  defp create_token(data) do
    expiration_shift = Application.get_env(:arke_auth, :reset_password_token_ttl, weeks: 2)
    token = :crypto.strong_rand_bytes(22) |> Base.url_encode64(case: :lower, padding: false)
    user_id = Map.fetch!(data, :user_id)

    {:ok,
     %{
       token: token,
       expiration: Arke.Utils.DatetimeHandler.shift_datetime(expiration_shift),
       user_id: user_id
     }}
  end
end
