import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.

config :arke,
  persistence: %{
    arke_postgres: %{
      transaction: &Arke.Test.Persistence.transaction/2,
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
