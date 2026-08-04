import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.

config :arke,
  persistence: %{
    arke_postgres: %{
      create: &Arke.Test.Persistence.create/2,
      update: &Arke.Test.Persistence.update/2,
      update_key: &Arke.Test.Persistence.update_key/2,
      delete: &Arke.Test.Persistence.delete/2,
      execute_query: &Arke.Test.Persistence.execute/2,
      get_parameters: &Arke.Test.Persistence.get_parameters/0,
      create_project: &Arke.Test.Persistence.create_project/1,
      delete_project: &Arke.Test.Persistence.delete_project/1
    }
  }

config :arke_auth, ArkeAuth.Guardian,
  issuer: "arke_auth",
  secret_key: "5hyuhkszkm8jilkDxrXGTBz1z1KJk5dtVwLgLOXHQRsPEtxii3wFcAbx4Gtj1aQB",
  verify_issuer: true,
  token_ttl: %{"access" => {7, :days}, "refresh" => {30, :days}}

# Test-only: the library keeps requiring consumers to configure SSO themselves.
# Without this the "sso" branch of Auth.create_tokens/2 is unreachable
# (encode_and_sign returns {:error, :secret_not_found}).
config :arke_auth, ArkeAuth.SSOGuardian,
  issuer: "arke_auth_sso",
  secret_key: "Kx7pQ2mRvN8tYbHjWs4ZcLfD6gEaXuT3nB9kVyPrM5oJqShFdCwG1iAzUeO0lNyB",
  verify_issuer: true,
  token_ttl: %{"access" => {1, :hours}, "refresh" => {1, :days}}
