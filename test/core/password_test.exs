defmodule ArkeAuth.Core.PasswordTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Core.Password

  defp create_user(username, password \\ "password") do
    {:ok, user} =
      QueryManager.create(:arke_system, ArkeManager.get(:user, :arke_system), %{
        username: username,
        password: password,
        email: "#{username}@arke.test"
      })

    {:ok, _member} =
      QueryManager.create(:test_schema, ArkeManager.get(:super_admin, :arke_system), %{
        arke_system_user: to_string(user.id)
      })

    user
  end

  # Writes a hash straight into the persistence, as someone with database
  # access would, bypassing User.before_update/3.
  defp write_hash(user, hash) do
    data = Map.put(user.data, :password_hash, hash)
    {:ok, _} = Arke.Test.Persistence.update(:arke_system, %{user | data: data})
  end

  defp stored_hash(username),
    do:
      QueryManager.get_by(project: :arke_system, arke_id: :user, username: username).data.password_hash

  test "a new password gets a peppered hash" do
    create_user("pepper_new")
    assert stored_hash("pepper_new") =~ ~r/^pep1\$\$2b\$/
  end

  test "a peppered hash signs in" do
    create_user("pepper_login")
    assert {:ok, _, _, _} = Auth.validate_credentials("pepper_login", "password", :test_schema)
  end

  test "a legacy hash signs in and is re-hashed with the pepper" do
    user = create_user("pepper_legacy")
    write_hash(user, Comeonin.Bcrypt.hashpwsalt("password"))
    refute Password.current?(stored_hash("pepper_legacy"))

    assert {:ok, _, _, _} = Auth.validate_credentials("pepper_legacy", "password", :test_schema)
    assert Password.current?(stored_hash("pepper_legacy"))
    assert {:ok, _, _, _} = Auth.validate_credentials("pepper_legacy", "password", :test_schema)
  end

  test "a hash written without the pepper does not open a peppered account" do
    user = create_user("pepper_attack")
    write_hash(user, "pep1$" <> Comeonin.Bcrypt.hashpwsalt("chosen_by_attacker"))

    assert {:error, _} =
             Auth.validate_credentials("pepper_attack", "chosen_by_attacker", :test_schema)
  end

  test "User.check_password/2 accepts both kinds of hash" do
    user = create_user("pepper_check")
    assert {:ok, _} = User.check_password(user, "password")
    assert {:error, _} = User.check_password(user, "wrong")

    write_hash(user, Comeonin.Bcrypt.hashpwsalt("password"))
    legacy = QueryManager.get_by(project: :arke_system, arke_id: :user, username: "pepper_check")
    assert {:ok, _} = User.check_password(legacy, "password")
  end

  test "verify/2 refuses a missing hash" do
    assert Password.verify("password", nil) == :error
  end

  test "validate_config!/0 refuses a missing or short pepper" do
    previous = Application.get_env(:arke_auth, Password)
    on_exit(fn -> Application.put_env(:arke_auth, Password, previous) end)

    Application.put_env(:arke_auth, Password, [])
    assert_raise ArgumentError, &Password.validate_config!/0

    Application.put_env(:arke_auth, Password, pepper: "short")
    assert_raise ArgumentError, &Password.validate_config!/0
  end

  test "mix arke_auth.password_status counts each kind" do
    legacy = create_user("pepper_status_legacy")
    wrapped = create_user("pepper_status_wrapped")
    create_user("pepper_status_current")
    write_hash(legacy, Comeonin.Bcrypt.hashpwsalt("password"))
    {:ok, hash} = Password.wrap(Comeonin.Bcrypt.hashpwsalt("password"))
    write_hash(wrapped, hash)

    counts = Mix.Tasks.ArkeAuth.PasswordStatus.count()
    assert counts.legacy >= 1
    assert counts.wrapped >= 1
    assert counts.current >= 1
  end

  describe "wrapped legacy hashes" do
    test "a wrapped hash signs in and is re-hashed with the pepper" do
      user = create_user("wrap_login")
      {:ok, hash} = Password.wrap(Comeonin.Bcrypt.hashpwsalt("password"))
      write_hash(user, hash)

      assert Password.kind(stored_hash("wrap_login")) == :wrapped
      assert {:error, _} = Auth.validate_credentials("wrap_login", "wrong", :test_schema)
      assert {:ok, _, _, _} = Auth.validate_credentials("wrap_login", "password", :test_schema)
      assert Password.kind(stored_hash("wrap_login")) == :current
    end

    test "a wrapped hash cannot be forged without the pepper" do
      user = create_user("wrap_forged")
      legacy = Comeonin.Bcrypt.hashpwsalt("chosen_by_attacker")
      forged = "pepw$" <> binary_part(legacy, 0, 29) <> String.duplicate("A", 43)
      write_hash(user, forged)

      assert {:error, _} =
               Auth.validate_credentials("wrap_forged", "chosen_by_attacker", :test_schema)

      assert Password.verify("x", "pepw$garbage") == :error
      assert Password.wrap("not a bcrypt hash") == :error
    end

    test "with accept_legacy_hashes: false a legacy hash is refused, a wrapped one is not" do
      put_password_config(accept_legacy_hashes: false)
      legacy = create_user("legacy_refused")
      write_hash(legacy, Comeonin.Bcrypt.hashpwsalt("password"))
      wrapped = create_user("wrapped_accepted")
      {:ok, hash} = Password.wrap(Comeonin.Bcrypt.hashpwsalt("password"))
      write_hash(wrapped, hash)

      assert {:error, _} = Auth.validate_credentials("legacy_refused", "password", :test_schema)

      assert {:ok, _, _, _} =
               Auth.validate_credentials("wrapped_accepted", "password", :test_schema)
    end

    test "mix arke_auth.wrap_legacy_passwords wraps only with --confirm" do
      user = create_user("wrap_task")
      write_hash(user, Comeonin.Bcrypt.hashpwsalt("password"))

      assert %{legacy: legacy, wrapped: 0} = Mix.Tasks.ArkeAuth.WrapLegacyPasswords.wrap(false)
      assert legacy >= 1
      assert Password.kind(stored_hash("wrap_task")) == :legacy

      assert %{wrapped: wrapped} = Mix.Tasks.ArkeAuth.WrapLegacyPasswords.wrap(true)
      assert wrapped == legacy
      assert Password.kind(stored_hash("wrap_task")) == :wrapped
      assert %{legacy: 0} = Mix.Tasks.ArkeAuth.WrapLegacyPasswords.wrap(true)

      put_password_config(accept_legacy_hashes: false)
      assert {:ok, _, _, _} = Auth.validate_credentials("wrap_task", "password", :test_schema)
    end
  end

  defp put_password_config(opts) do
    previous = Application.get_env(:arke_auth, Password)
    on_exit(fn -> Application.put_env(:arke_auth, Password, previous) end)
    Application.put_env(:arke_auth, Password, Keyword.merge(previous, opts))
  end
end
