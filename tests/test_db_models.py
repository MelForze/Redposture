from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from redposture_core.db.models import (
    Artifact,
    Evidence,
    Finding,
    ModuleRun,
    NetworkEndpoint,
    Note,
    RunObservation,
    TargetHost,
    Workspace,
)
from redposture_core.db.session import session_scope


def test_soft_delete_defaults_are_unset(session_factory) -> None:
    with session_scope(session_factory) as session:
        workspace = Workspace(slug="defaults", display_name="Defaults")
        session.add(workspace)
        session.flush()
        host = TargetHost(workspace_id=workspace.id, canonical_key="10.0.0.1")
        session.add(host)
        session.flush()

        assert workspace.is_archived is False
        assert workspace.archived_at is None
        assert workspace.deleted_at is None
        assert host.is_archived is False
        assert host.archived_at is None
        assert host.deleted_at is None


def test_target_host_unique_constraint_is_enforced(session_factory) -> None:
    with pytest.raises(IntegrityError):
        with session_scope(session_factory) as session:
            workspace = Workspace(slug="uniq-host", display_name="Uniq Host")
            session.add(workspace)
            session.flush()
            session.add(TargetHost(workspace_id=workspace.id, canonical_key="10.0.0.1"))
            session.add(TargetHost(workspace_id=workspace.id, canonical_key="10.0.0.1"))
            session.flush()


def test_run_observation_and_finding_unique_constraints_are_enforced(session_factory) -> None:
    with pytest.raises(IntegrityError):
        with session_scope(session_factory) as session:
            workspace = Workspace(slug="uniq-observation", display_name="Uniq Observation")
            session.add(workspace)
            session.flush()
            run = ModuleRun(
                workspace_id=workspace.id,
                module_name="grafana",
                protocol="grafana",
                source_type="scan",
                execution_status="success",
            )
            session.add(run)
            session.flush()
            observation_1 = RunObservation(
                workspace_id=workspace.id,
                module_run_id=run.id,
                module_name="grafana",
                protocol="grafana",
                normalized_status="open_no_auth",
                fingerprint="same-observation",
                source_type="scan",
            )
            observation_2 = RunObservation(
                workspace_id=workspace.id,
                module_run_id=run.id,
                module_name="grafana",
                protocol="grafana",
                normalized_status="open_no_auth",
                fingerprint="same-observation",
                source_type="scan",
            )
            session.add_all([observation_1, observation_2])
            session.flush()

    with pytest.raises(IntegrityError):
        with session_scope(session_factory) as session:
            workspace = Workspace(slug="uniq-finding", display_name="Uniq Finding")
            session.add(workspace)
            session.flush()
            session.add(
                Finding(
                    workspace_id=workspace.id,
                    title="dup",
                    finding_type="anonymous_access",
                    protocol="grafana",
                    module_name="grafana",
                    status="open",
                    fingerprint="same-finding",
                )
            )
            session.add(
                Finding(
                    workspace_id=workspace.id,
                    title="dup",
                    finding_type="anonymous_access",
                    protocol="grafana",
                    module_name="grafana",
                    status="open",
                    fingerprint="same-finding",
                )
            )
            session.flush()


def test_note_requires_exactly_one_parent(session_factory) -> None:
    with pytest.raises(IntegrityError):
        with session_scope(session_factory) as session:
            workspace = Workspace(slug="notes", display_name="Notes")
            session.add(workspace)
            session.flush()
            host = TargetHost(workspace_id=workspace.id, canonical_key="10.0.0.1")
            endpoint = NetworkEndpoint(
                workspace_id=workspace.id, canonical_key="tcp://10.0.0.1:443", target_host_id=None
            )
            session.add_all([host, endpoint])
            session.flush()
            session.add(
                Note(
                    workspace_id=workspace.id,
                    target_host_id=host.id,
                    endpoint_id=endpoint.id,
                    body="two parents",
                )
            )
            session.flush()


def test_evidence_relationships_link_artifact_and_finding(session_factory) -> None:
    with session_scope(session_factory) as session:
        workspace = Workspace(slug="rels", display_name="Relationships")
        session.add(workspace)
        session.flush()
        run = ModuleRun(
            workspace_id=workspace.id,
            module_name="grafana",
            protocol="grafana",
            source_type="scan",
            execution_status="success",
        )
        session.add(run)
        session.flush()
        finding = Finding(
            workspace_id=workspace.id,
            module_run_id=run.id,
            title="anonymous access",
            finding_type="anonymous_access",
            protocol="grafana",
            module_name="grafana",
            status="open",
            fingerprint="rels-finding",
        )
        session.add(finding)
        session.flush()
        artifact = Artifact(
            workspace_id=workspace.id,
            module_run_id=run.id,
            finding_id=finding.id,
            artifact_role="raw_payload",
            sha256="abc",
            size_bytes=3,
            content_blob=b"abc",
        )
        session.add(artifact)
        session.flush()
        evidence = Evidence(
            workspace_id=workspace.id,
            module_run_id=run.id,
            finding_id=finding.id,
            artifact_id=artifact.id,
            evidence_type="observation",
            title="payload",
        )
        session.add(evidence)
        session.flush()

        assert evidence.finding is finding
        assert evidence.artifact is artifact
        assert artifact.evidence_items == [evidence]
        assert finding.evidence_items == [evidence]
