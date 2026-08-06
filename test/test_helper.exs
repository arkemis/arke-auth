ExUnit.start()

Arke.Test.Persistence.setup()
Arke.Test.Bootstrap.start(apps: [:arke, :arke_auth])
ArkeAuth.Test.ExplodingMember.register()
Arke.Test.Sandbox.checkpoint()
