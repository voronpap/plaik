"""Explicit installation, group and store context for Core services.

There is deliberately no process-global "current store".  Callers must pass a
context to every scoped operation, which keeps background jobs and concurrent
requests from leaking data between stores.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


_SCOPE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,63}$"


class ScopeLevel(StrEnum):
    INSTALLATION = "installation"
    GROUP = "group"
    STORE = "store"


class StoreContext(BaseModel):
    """An immutable, validated point in the installation -> group -> store tree."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    installation_id: str = Field(
        default="default",
        min_length=1,
        max_length=64,
        pattern=_SCOPE_ID_PATTERN,
    )
    group_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=_SCOPE_ID_PATTERN,
    )
    store_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=_SCOPE_ID_PATTERN,
    )

    @model_validator(mode="after")
    def validate_hierarchy(self) -> StoreContext:
        if self.store_id is not None and self.group_id is None:
            raise ValueError("store context requires a group_id")
        return self

    @classmethod
    def installation(cls, installation_id: str = "default") -> StoreContext:
        return cls(installation_id=installation_id)

    @classmethod
    def group(cls, group_id: str, installation_id: str = "default") -> StoreContext:
        return cls(installation_id=installation_id, group_id=group_id)

    @classmethod
    def store(
        cls,
        group_id: str,
        store_id: str,
        installation_id: str = "default",
    ) -> StoreContext:
        return cls(
            installation_id=installation_id,
            group_id=group_id,
            store_id=store_id,
        )

    @property
    def level(self) -> ScopeLevel:
        if self.store_id is not None:
            return ScopeLevel.STORE
        if self.group_id is not None:
            return ScopeLevel.GROUP
        return ScopeLevel.INSTALLATION

    @property
    def key(self) -> str:
        """Stable registry key; identifiers cannot contain the separator."""

        parts = [self.installation_id]
        if self.group_id is not None:
            parts.append(self.group_id)
        if self.store_id is not None:
            parts.append(self.store_id)
        return f"{self.level.value}:" + ":".join(parts)

    @property
    def parent(self) -> StoreContext | None:
        if self.store_id is not None:
            return StoreContext.group(self.group_id or "", self.installation_id)
        if self.group_id is not None:
            return StoreContext.installation(self.installation_id)
        return None

    def inheritance_chain(self) -> tuple[StoreContext, ...]:
        """Return scopes from least to most specific, including this context."""

        chain = [StoreContext.installation(self.installation_id)]
        if self.group_id is not None:
            chain.append(StoreContext.group(self.group_id, self.installation_id))
        if self.store_id is not None:
            chain.append(
                StoreContext.store(
                    self.group_id or "",
                    self.store_id,
                    self.installation_id,
                )
            )
        return tuple(chain)
