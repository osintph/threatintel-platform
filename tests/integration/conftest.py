"""Fixtures shared by the integration tests."""

# Loopback listeners and the scripted resolver used by the outbound-request tests.
# The real application on an empty database, a signed-in client, a temp data dir.
from ._app_fixtures import client, data_dir, db, full_app  # noqa: F401
from ._loopback import loopback, scripted_dns  # noqa: F401
