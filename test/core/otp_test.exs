defmodule ArkeAuth.Core.OtpTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Core.Otp
  alias ArkeAuth.Boundary.OtpManager

  @member %{id: :otp_test_member}

  describe "OtpManager.get_code/3" do
    setup do
      previous = System.get_env("OTP_BYPASS_CODE")
      System.put_env("OTP_BYPASS_CODE", "0000")

      on_exit(fn ->
        if previous,
          do: System.put_env("OTP_BYPASS_CODE", previous),
          else: System.delete_env("OTP_BYPASS_CODE")
      end)

      :ok
    end

    test "OTP_BYPASS_CODE no longer forges a code for a member without one" do
      assert OtpManager.get_code(:test_schema, @member, "signin") == nil
    end

    test "OTP_BYPASS_CODE does not replace the member's real code" do
      {:ok, otp} = Otp.generate(:test_schema, @member.id, "signin")

      code = OtpManager.get_code(:test_schema, @member, "signin")
      assert code.data.code == otp.data.code
      refute code.data.code == "0000"
    end
  end

  describe "Otp.generate_code/1" do
    test "codes are six-digit numeric strings by default" do
      for _ <- 1..200 do
        code = Otp.generate_code()
        assert code =~ ~r/^\d{6}$/
      end
    end

    test "fewer than six digits cannot be requested" do
      assert String.length(Otp.generate_code(4)) == 6
      assert String.length(Otp.generate_code(8)) == 8
    end

    test "generate/3 stores a six-digit code" do
      {:ok, otp} = Otp.generate(:test_schema, :gen_member, "signin")
      assert otp.data.code =~ ~r/^\d{6}$/
    end
  end

  describe "OtpManager.verify_code/4" do
    test "the right code verifies once and is consumed" do
      {:ok, otp} = Otp.generate(:test_schema, :verify_ok, "signin")

      assert {:ok, _} =
               OtpManager.verify_code(:test_schema, %{id: :verify_ok}, "signin", otp.data.code)

      assert OtpManager.get_code(:test_schema, %{id: :verify_ok}, "signin") == nil

      assert {:error, [%{context: "auth", message: "invalid otp"}]} =
               OtpManager.verify_code(:test_schema, %{id: :verify_ok}, "signin", otp.data.code)
    end

    test "an integer submission is compared as a string" do
      {:ok, otp} = Otp.generate(:test_schema, :verify_int, "signin")

      assert {:ok, _} =
               OtpManager.verify_code(
                 :test_schema,
                 %{id: :verify_int},
                 :signin,
                 String.to_integer(otp.data.code)
               )
    end

    test "an integer submission keeps the code's leading zeros" do
      {:ok, otp} = Otp.generate(:test_schema, :verify_zero, "signin")
      {:ok, otp} = QueryManager.update(otp, code: "004217")

      assert {:ok, _} = OtpManager.verify_code(:test_schema, %{id: :verify_zero}, "signin", 4217)
    end

    test "a raw id (signup by username) is accepted" do
      {:ok, otp} = Otp.generate(:test_schema, "new_user@arke.test", "signup")

      assert {:ok, _} =
               OtpManager.verify_code(:test_schema, "new_user@arke.test", "signup", otp.data.code)
    end

    test "a wrong code is rejected" do
      {:ok, otp} = Otp.generate(:test_schema, :verify_wrong, "signin")

      assert {:error, [%{message: "invalid otp"}]} =
               OtpManager.verify_code(:test_schema, %{id: :verify_wrong}, "signin", wrong(otp))

      assert {:ok, _} =
               OtpManager.verify_code(:test_schema, %{id: :verify_wrong}, "signin", otp.data.code)
    end

    test "the code is burnt after five wrong guesses, even if the next one is right" do
      {:ok, otp} = Otp.generate(:test_schema, :verify_brute, "signin")
      member = %{id: :verify_brute}

      for _ <- 1..4 do
        assert {:error, [%{message: "invalid otp"}]} =
                 OtpManager.verify_code(:test_schema, member, "signin", wrong(otp))
      end

      assert {:error, [%{message: "too many attempts"}]} =
               OtpManager.verify_code(:test_schema, member, "signin", wrong(otp))

      assert OtpManager.get_code(:test_schema, member, "signin") == nil

      assert {:error, [%{message: "invalid otp"}]} =
               OtpManager.verify_code(:test_schema, member, "signin", otp.data.code)
    end

    test "a regenerated code gets a fresh attempt budget" do
      member = %{id: :verify_regen}
      {:ok, first} = Otp.generate(:test_schema, member.id, "signin")

      for _ <- 1..4, do: OtpManager.verify_code(:test_schema, member, "signin", wrong(first))

      {:ok, second} = Otp.generate(:test_schema, member.id, "signin")

      for _ <- 1..4 do
        assert {:error, [%{message: "invalid otp"}]} =
                 OtpManager.verify_code(:test_schema, member, "signin", wrong(second))
      end

      assert {:ok, _} = OtpManager.verify_code(:test_schema, member, "signin", second.data.code)
    end

    test "an expired code is rejected and removed" do
      past = NaiveDateTime.utc_now() |> NaiveDateTime.add(-1, :second)
      {:ok, otp} = Otp.generate(:test_schema, :verify_expired, "signin", past)

      assert {:error, [%{message: "otp expired"}]} =
               OtpManager.verify_code(
                 :test_schema,
                 %{id: :verify_expired},
                 "signin",
                 otp.data.code
               )

      assert OtpManager.get_code(:test_schema, %{id: :verify_expired}, "signin") == nil
    end

    test "no code means invalid" do
      assert {:error, [%{message: "invalid otp"}]} =
               OtpManager.verify_code(:test_schema, %{id: :verify_none}, "signin", "123456")
    end
  end

  defp wrong(%{data: %{code: code}}) do
    code
    |> String.to_integer()
    |> Kernel.+(1)
    |> rem(1_000_000)
    |> Integer.to_string()
    |> String.pad_leading(6, "0")
  end
end
