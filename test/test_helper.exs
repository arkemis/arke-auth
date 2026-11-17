ExUnit.start()

Arke.Test.Persistence.setup()
Arke.Test.Bootstrap.start(apps: [:arke, :arke_auth])
Arke.Test.Sandbox.checkpoint()
