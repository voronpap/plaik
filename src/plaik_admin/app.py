"""Admin ASGI entry point."""

from plaik_core.applications import create_admin_app


create_app = create_admin_app
app = create_app()
