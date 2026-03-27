"""Inventory repositories."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.core import NetworkEndpoint, ProtocolService, RunObservation, TargetHost
from ..util import utcnow
from .common import dialect_insert


class HostRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(
        self, *, workspace_id: int, canonical_key: str, hostname: str | None, fqdn: str | None, ip_address: str | None
    ) -> TargetHost:
        now = utcnow()
        stmt = dialect_insert(self.session, TargetHost).values(
            workspace_id=workspace_id,
            canonical_key=canonical_key,
            hostname=hostname,
            fqdn=fqdn,
            ip_address=ip_address,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            is_archived=False,
            archived_at=None,
            deleted_at=None,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[TargetHost.workspace_id, TargetHost.canonical_key],
            set_={
                "hostname": func.coalesce(stmt.excluded.hostname, TargetHost.hostname),
                "fqdn": func.coalesce(stmt.excluded.fqdn, TargetHost.fqdn),
                "ip_address": func.coalesce(stmt.excluded.ip_address, TargetHost.ip_address),
                "last_seen_at": now,
                "updated_at": now,
                "is_archived": False,
                "archived_at": None,
                "deleted_at": None,
            },
        )
        self.session.execute(stmt)
        host = self.session.scalar(
            select(TargetHost)
            .where(TargetHost.workspace_id == workspace_id, TargetHost.canonical_key == canonical_key)
            .execution_options(populate_existing=True)
        )
        if host is None:
            raise RuntimeError("host upsert failed")
        return host

    def list(self, *, workspace_id: int, module_name: str | None = None) -> list[TargetHost]:
        stmt = select(TargetHost).where(TargetHost.workspace_id == workspace_id, TargetHost.deleted_at.is_(None))
        if module_name:
            stmt = stmt.join(RunObservation, RunObservation.target_host_id == TargetHost.id).where(
                RunObservation.workspace_id == workspace_id,
                RunObservation.module_name == module_name,
                RunObservation.deleted_at.is_(None),
            )
            stmt = stmt.distinct()
        return list(self.session.scalars(stmt.order_by(TargetHost.last_seen_at.desc(), TargetHost.canonical_key)))


class EndpointRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(
        self,
        *,
        workspace_id: int,
        target_host_id: int | None,
        canonical_key: str,
        scheme: str | None,
        host: str | None,
        ip: str | None,
        port: int | None,
        path: str | None,
        netloc: str | None,
    ) -> NetworkEndpoint:
        now = utcnow()
        stmt = dialect_insert(self.session, NetworkEndpoint).values(
            workspace_id=workspace_id,
            target_host_id=target_host_id,
            canonical_key=canonical_key,
            scheme=scheme,
            host=host,
            ip=ip,
            port=port,
            path=path,
            netloc=netloc,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            is_archived=False,
            archived_at=None,
            deleted_at=None,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[NetworkEndpoint.workspace_id, NetworkEndpoint.canonical_key],
            set_={
                "target_host_id": func.coalesce(stmt.excluded.target_host_id, NetworkEndpoint.target_host_id),
                "scheme": func.coalesce(stmt.excluded.scheme, NetworkEndpoint.scheme),
                "host": func.coalesce(stmt.excluded.host, NetworkEndpoint.host),
                "ip": func.coalesce(stmt.excluded.ip, NetworkEndpoint.ip),
                "port": func.coalesce(stmt.excluded.port, NetworkEndpoint.port),
                "path": func.coalesce(stmt.excluded.path, NetworkEndpoint.path),
                "netloc": func.coalesce(stmt.excluded.netloc, NetworkEndpoint.netloc),
                "last_seen_at": now,
                "updated_at": now,
                "is_archived": False,
                "archived_at": None,
                "deleted_at": None,
            },
        )
        self.session.execute(stmt)
        endpoint = self.session.scalar(
            select(NetworkEndpoint)
            .where(
                NetworkEndpoint.workspace_id == workspace_id,
                NetworkEndpoint.canonical_key == canonical_key,
            )
            .execution_options(populate_existing=True)
        )
        if endpoint is None:
            raise RuntimeError("endpoint upsert failed")
        return endpoint

    def list(
        self,
        *,
        workspace_id: int,
        host_id: int | None = None,
        module_name: str | None = None,
    ) -> list[NetworkEndpoint]:
        stmt = select(NetworkEndpoint).where(
            NetworkEndpoint.workspace_id == workspace_id, NetworkEndpoint.deleted_at.is_(None)
        )
        if host_id is not None:
            stmt = stmt.where(NetworkEndpoint.target_host_id == host_id)
        if module_name:
            stmt = stmt.join(RunObservation, RunObservation.endpoint_id == NetworkEndpoint.id).where(
                RunObservation.workspace_id == workspace_id,
                RunObservation.module_name == module_name,
                RunObservation.deleted_at.is_(None),
            )
            stmt = stmt.distinct()
        return list(
            self.session.scalars(stmt.order_by(NetworkEndpoint.last_seen_at.desc(), NetworkEndpoint.canonical_key))
        )


class ProtocolServiceRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(
        self,
        *,
        workspace_id: int,
        endpoint_id: int | None,
        protocol: str,
        service_name: str,
        auth_required: bool | None,
        status: str | None,
        version: str | None,
        extra_summary_json: dict | list | None = None,
    ) -> ProtocolService:
        now = utcnow()
        stmt = dialect_insert(self.session, ProtocolService).values(
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            protocol=protocol,
            service_name=service_name,
            auth_required=auth_required,
            status=status,
            version=version,
            extra_summary_json=extra_summary_json,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            is_archived=False,
            archived_at=None,
            deleted_at=None,
        )
        update_values = {
            "auth_required": func.coalesce(stmt.excluded.auth_required, ProtocolService.auth_required),
            "status": func.coalesce(stmt.excluded.status, ProtocolService.status),
            "version": func.coalesce(stmt.excluded.version, ProtocolService.version),
            "extra_summary_json": func.coalesce(stmt.excluded.extra_summary_json, ProtocolService.extra_summary_json),
            "last_seen_at": now,
            "updated_at": now,
            "is_archived": False,
            "archived_at": None,
            "deleted_at": None,
        }
        if endpoint_id is None:
            stmt = stmt.on_conflict_do_update(
                index_elements=[
                    ProtocolService.workspace_id,
                    ProtocolService.protocol,
                    ProtocolService.service_name,
                ],
                index_where=ProtocolService.endpoint_id.is_(None),
                set_=update_values,
            )
        else:
            stmt = stmt.on_conflict_do_update(
                index_elements=[
                    ProtocolService.workspace_id,
                    ProtocolService.protocol,
                    ProtocolService.endpoint_id,
                    ProtocolService.service_name,
                ],
                set_=update_values,
            )
        self.session.execute(stmt)
        service = self.session.scalar(
            select(ProtocolService)
            .where(
                ProtocolService.workspace_id == workspace_id,
                ProtocolService.endpoint_id == endpoint_id,
                ProtocolService.protocol == protocol,
                ProtocolService.service_name == service_name,
            )
            .execution_options(populate_existing=True)
        )
        if service is None:
            raise RuntimeError("protocol service upsert failed")
        return service
