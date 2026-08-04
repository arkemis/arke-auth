defmodule ArkeAuth.Core.OtpTest do
  use ArkeAuth.RepoCase

  alias ArkeAuth.Boundary.OtpManager
  alias ArkeAuth.Core.Otp

  @member %{id: "member_1"}

  defp stored_otps do
    QueryManager.query(project: :test_schema, arke: ArkeManager.get(:otp, :arke_system).id)
    |> QueryManager.all()
  end

  defp ttl_seconds(otp),
    do: NaiveDateTime.diff(otp.data.expiry_datetime, NaiveDateTime.utc_now())

  defp put_otp_ttl(ttl) do
    on_exit(fn -> Application.delete_env(:arke_auth, ArkeAuth.Otp) end)
    Application.put_env(:arke_auth, ArkeAuth.Otp, ttl: ttl)
  end

  test "parse_otp_id/2 namespaces the code by action" do
    assert Otp.parse_otp_id("signin", "member_1") == "otp_signin_member_1"
  end

  describe "generate/4" do
    test "regenerates in place instead of piling up rows" do
      {:ok, first} = Otp.generate(:test_schema, @member.id, "signin")
      {:ok, second} = Otp.generate(:test_schema, @member.id, "signin")

      assert first.id == second.id
      assert length(stored_otps()) == 1
      assert OtpManager.get_code(:test_schema, @member).data.code == second.data.code
    end

    test "keeps codes of different actions apart" do
      {:ok, signin} = Otp.generate(:test_schema, @member.id, "signin")
      {:ok, reset} = Otp.generate(:test_schema, @member.id, "reset")

      assert length(stored_otps()) == 2
      assert OtpManager.get_code(:test_schema, @member, "signin").id == signin.id
      assert OtpManager.get_code(:test_schema, @member, :reset).id == reset.id
    end

    test "codes are 4-digit strings" do
      {:ok, otp} = Otp.generate(:test_schema, @member.id, "signin")

      assert otp.data.code =~ ~r/^\d{4}$/
    end

    test "defaults to a 5 minute ttl" do
      {:ok, otp} = Otp.generate(:test_schema, @member.id, "signin")

      assert ttl_seconds(otp) in 295..300
    end

    test "an explicit nil expiry ignores the config and falls back to 300 seconds" do
      put_otp_ttl({2, :days})

      {:ok, otp} = Otp.generate(:test_schema, @member.id, "signin", nil)

      assert ttl_seconds(otp) in 295..300
    end

    for {value, unit, seconds} <- [{90, :seconds, 90}, {2, :minutes, 120}, {1, :days, 86_400}] do
      test "reads a ttl configured in #{unit}" do
        put_otp_ttl({unquote(value), unquote(unit)})

        {:ok, otp} = Otp.generate(:test_schema, @member.id, "signin")

        assert ttl_seconds(otp) in (unquote(seconds) - 5)..unquote(seconds)
      end
    end
  end

  describe "OtpManager" do
    test "get_code returns nil when no code was generated" do
      assert OtpManager.get_code(:test_schema, @member) == nil
    end

    test "delete_otp removes the stored code" do
      {:ok, otp} = Otp.generate(:test_schema, @member.id, "signin")

      assert {:ok, nil} = OtpManager.delete_otp(otp)
      assert OtpManager.get_code(:test_schema, @member) == nil
    end

    test "delete_otp tolerates a missing code" do
      assert OtpManager.delete_otp(nil) == nil
    end
  end

  describe "OTP_BYPASS_CODE" do
    setup do
      previous = System.get_env("OTP_BYPASS_CODE")

      on_exit(fn ->
        case previous do
          nil -> System.delete_env("OTP_BYPASS_CODE")
          value -> System.put_env("OTP_BYPASS_CODE", value)
        end
      end)

      :ok
    end

    test "bypasses the stored code entirely when set" do
      System.put_env("OTP_BYPASS_CODE", "0000")

      assert OtpManager.get_code(:test_schema, @member).data.code == "0000"
      assert stored_otps() == []
    end

    test "an empty value is treated as unset" do
      System.put_env("OTP_BYPASS_CODE", "")

      assert OtpManager.get_code(:test_schema, @member) == nil
    end
  end
end
