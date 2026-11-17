defmodule ArkeAuth.Core.PasswordHashTest do
  use ExUnit.Case, async: true

  alias ArkeAuth.Core.{Password, User}

  @legacy_hash "$2b$12$eIwr4irILrNZmiZVZAhuCO8xbCAxEHKqj8aZjY9lJ0Uyngbi8UjUK"
  @legacy_password "password"

  describe "stored hash compatibility" do
    test "a hash written by the previous bcrypt version still verifies" do
      user = %{id: :legacy_user, data: %{password_hash: @legacy_hash}}

      assert User.check_password(user, @legacy_password) == {:ok, user}
    end

    test "a wrong password against a stored hash is rejected" do
      user = %{id: :legacy_user, data: %{password_hash: @legacy_hash}}

      assert User.check_password(user, "wrong") ==
               {:error, [%{context: "auth", message: "invalid password"}]}
    end
  end

  describe "hashing" do
    test "produces a peppered $2b$ hash that verifies and differs per call" do
      {:ok, data} = User.before_load(%{password: @legacy_password}, :create)
      refute Map.has_key?(data, :password)

      hash = Password.bind_pending(data.password_hash, :new_user)
      assert "pep1$" <> bcrypt = hash
      assert String.starts_with?(bcrypt, "$2b$")

      user = %{id: :new_user, data: %{password_hash: hash}}
      assert User.check_password(user, @legacy_password) == {:ok, user}

      {:ok, other} = User.before_load(%{password: @legacy_password}, :create)
      refute Password.bind_pending(other.password_hash, :new_user) == hash
    end
  end
end
