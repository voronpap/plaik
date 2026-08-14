"""Web ASGI entry point."""

from plaik_core.applications import create_web_app


create_app = create_web_app
app = create_app()
