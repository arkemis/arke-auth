import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.

config :arke,
  persistence: %{
    arke_postgres: %{
      create: &ArkeAuth.Support.Persistence.create/2,
      update: &ArkeAuth.Support.Persistence.update/2,
      delete: &ArkeAuth.Support.Persistence.delete/2,
      execute_query: &ArkeAuth.Support.Persistence.execute_query/2,
      get_parameters: &ArkeAuth.Support.Persistence.get_parameters/0,
      create_project: &ArkeAuth.Support.Persistence.create_project/1,
      delete_project: &ArkeAuth.Support.Persistence.delete_project/1
    }
  }

config :arke_auth, ArkeAuth.Guardian,
  issuer: "arke_auth",
  secret_key: "5hyuhkszkm8jilkDxrXGTBz1z1KJk5dtVwLgLOXHQRsPEtxii3wFcAbx4Gtj1aQB",
  verify_issuer: true,
  token_ttl: %{"access" => {7, :days}, "refresh" => {30, :days}}

config :arke_auth, ArkeAuth.SSOGuardian,
  issuer: "arke_auth",
  secret_key: "Wd0e9tYyb7r8JgQv1L3mZ5pS2kH6nX4cA0fT7uE9iR3oP1sD8gV2jB5qN6wM4yC7",
  verify_issuer: true,
  token_ttl: %{"access" => {7, :days}, "refresh" => {30, :days}}
