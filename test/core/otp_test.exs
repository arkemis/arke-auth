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
end
