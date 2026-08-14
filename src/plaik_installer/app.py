"""Installer ASGI entry point."""

from plaik_core.applications import create_installer_app


create_app = create_installer_app
app = create_app()
