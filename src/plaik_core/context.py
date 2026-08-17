"""Explicit installation, group and store context for Core services.

There is deliberately no process-global "current store".  Callers must pass a
context to every scoped operation, which keeps background jobs and concurrent
requests from leaking data between stores.

``StoreContext`` is the public ``ScopeRef`` tenant tree, not a second hierarchy.
"""

from __future__ import annotations

from plaik_contracts import ScopeLevel, ScopeRef


StoreContext = ScopeRef

__all__ = ["ScopeLevel", "ScopeRef", "StoreContext"]
