defmodule ArkeAuth.Utils.TokenCryptoTest do
  use ExUnit.Case, async: false

  alias ArkeAuth.Utils.TokenCrypto

  @old_key String.duplicate("o", 32)

  defp with_config(config, fun) do
    previous = Application.get_env(:arke_auth, TokenCrypto)
    Application.put_env(:arke_auth, TokenCrypto, config)

    try do
      fun.()
    after
      Application.put_env(:arke_auth, TokenCrypto, previous)
    end
  end

  test "random_token/1 is url-safe, random and sized" do
    token = TokenCrypto.random_token()
    assert token =~ ~r/^[A-Za-z0-9_-]{43}$/
    refute token == TokenCrypto.random_token()
    assert {:ok, bytes} = Base.url_decode64(TokenCrypto.random_token(16), padding: false)
    assert byte_size(bytes) == 16
  end

  test "hmac/2 is deterministic and depends on the purpose" do
    assert TokenCrypto.hmac(:otp, "data") == TokenCrypto.hmac(:otp, ["da", "ta"])
    refute TokenCrypto.hmac(:otp, "data") == TokenCrypto.hmac(:temporary_token, "data")
    assert byte_size(TokenCrypto.hmac(:otp, "data")) == 32
  end

  test "sign/2 and verify/2 round-trip" do
    token = TokenCrypto.sign(:reset_password, "user|123")
    assert TokenCrypto.verify(:reset_password, token) == {:ok, "user|123"}
  end

  test "verify/2 rejects tampered, foreign and malformed tokens" do
    token = TokenCrypto.sign(:reset_password, "user|123")
    [payload, signature] = String.split(token, ".")
    forged_payload = Base.url_encode64("admin|123", padding: false)

    assert TokenCrypto.verify(:reset_password, forged_payload <> "." <> signature) == :error

    assert TokenCrypto.verify(:reset_password, payload <> "." <> String.reverse(signature)) ==
             :error

    assert TokenCrypto.verify(:otp, token) == :error
    assert TokenCrypto.verify(:reset_password, "no-dot") == :error
    assert TokenCrypto.verify(:reset_password, "a.b.c") == :error
    assert TokenCrypto.verify(:reset_password, nil) == :error
  end

  test "a token signed with a previous key verifies only while that key is listed" do
    current = Application.get_env(:arke_auth, TokenCrypto)[:token_key]
    token = with_config([token_key: @old_key], fn -> TokenCrypto.sign(:reset_password, "p") end)

    with_config([token_key: current, previous_keys: [@old_key]], fn ->
      assert TokenCrypto.verify(:reset_password, token) == {:ok, "p"}
    end)

    with_config([token_key: current], fn ->
      assert TokenCrypto.verify(:reset_password, token) == :error
    end)
  end

  test "secure_compare/2" do
    assert TokenCrypto.secure_compare("abc", "abc")
    refute TokenCrypto.secure_compare("abc", "abd")
    refute TokenCrypto.secure_compare("abc", "abcd")
    refute TokenCrypto.secure_compare(nil, "abc")
  end

  test "validate_config!/0 refuses a missing or short key" do
    with_config([], fn -> assert_raise ArgumentError, &TokenCrypto.validate_config!/0 end)

    with_config([token_key: "short"], fn ->
      assert_raise ArgumentError, &TokenCrypto.validate_config!/0
    end)

    assert TokenCrypto.validate_config!() == :ok
  end
end
