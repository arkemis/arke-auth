defmodule ArkeAuth.Core.PasswordHashTest do
  use ExUnit.Case, async: true

  alias ArkeAuth.Core.User

  @legacy_hash "$2b$12$eIwr4irILrNZmiZVZAhuCO8xbCAxEHKqj8aZjY9lJ0Uyngbi8UjUK"
  @legacy_password "password"

  describe "stored hash compatibility" do
    test "a hash written by the previous bcrypt version still verifies" do
      user = %{data: %{password_hash: @legacy_hash}}

      assert User.check_password(user, @legacy_password) == {:ok, user}
    end

    test "a wrong password against a stored hash is rejected" do
      user = %{data: %{password_hash: @legacy_hash}}

      assert User.check_password(user, "wrong") ==
               {:error, [%{context: "auth", message: "invalid password"}]}
    end
  end

  describe "hashing" do
    test "produces a $2b$ hash that verifies and differs per call" do
      {:ok, data} = User.before_load(%{password: @legacy_password}, :create)
      %{password_hash: hash} = data

      assert String.starts_with?(hash, "$2b$")
      refute Map.has_key?(data, :password)
      assert User.check_password(%{data: data}, @legacy_password) == {:ok, %{data: data}}

      {:ok, other} = User.before_load(%{password: @legacy_password}, :create)
      refute other.password_hash == hash
    end
  end
end
