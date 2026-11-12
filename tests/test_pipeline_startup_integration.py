"""Integration tests for Backend Startup and Pipeline Initialization."""

from __future__ import annotations

import asyncio
import os
import time
import pytest

from backend.api.dependencies import ServiceContainer, get_service_container
from backend.api.main import create_app, lifespan
from backend.api.routes.health import check_health
from backend.api.routes.stats import get_aggregate_statistics
from backend.api.routes.ml import get_ml_status
from backend.api.routes.firewall import list_firewall_rules
from backend.integrations.pipeline_factory import PipelineConfig, create_pipeline, shutdown_pipeline
from server.ingestion import TunnelCaptureSource, LiveCaptureSource


def test_pipeline_config_from_env(monkeypatch):
    """Verifies that PipelineConfig parses all DPI environment variables accurately."""
    monkeypatch.setenv("DPI_INGESTION_MODE", "live")
    monkeypatch.setenv("DPI_INTERFACE", "tnnl")
    monkeypatch.setenv("DPI_BPF_FILTER", "ip")
    monkeypatch.setenv("DPI_ACTIVE_PREVENTION", "false")
    monkeypatch.setenv("ML_ENABLED", "true")
    monkeypatch.setenv("DPI_WORKERS", "3")
    monkeypatch.setenv("DPI_QUEUE_SIZE", "5000")
    monkeypatch.setenv("DPI_VPN_SUBNETS", "10.100.0.0/24,10.200.0.0/24")

    cfg = PipelineConfig.from_env()
    assert cfg.ingestion_mode == "live"
    assert cfg.interface == "tnnl"
    assert cfg.bpf_filter == "ip"
    assert cfg.active_prevention is False
    assert cfg.ml_enabled is True
    assert cfg.workers == 3
    assert cfg.queue_size == 5000
    assert "10.100.0.0/24" in cfg.vpn_subnets
    assert "10.200.0.0/24" in cfg.vpn_subnets


def test_pipeline_factory_disabled_mode():
    """Verifies that ingestion_mode='disabled' creates an uninitialized PipelineAdapter."""
    cfg = PipelineConfig(ingestion_mode="disabled")
    adapter = create_pipeline(cfg)
    try:
        assert adapter.is_initialized is False
        assert adapter.worker_pool is None
        stats = adapter.get_pipeline_stats()
        assert stats["status"] == "uninitialized"
    finally:
        shutdown_pipeline(adapter)


def test_pipeline_factory_live_mode_with_tnnl():
    """Verifies that live mode with interface='tnnl' selects TunnelCaptureSource and starts workers."""
    cfg = PipelineConfig(
        ingestion_mode="live",
        interface="tnnl",
        bpf_filter="ip",
        workers=2,
        active_prevention=False,
        ml_enabled=True,
    )
    adapter = create_pipeline(cfg)
    try:
        assert adapter.is_initialized is True
        assert adapter.worker_pool is not None
        assert adapter.worker_pool.stats.active_workers == 2
        assert adapter.worker_pool.active_prevention is False

        # Ingestion source check
        assert adapter.packet_source is not None
        assert isinstance(adapter.packet_source, TunnelCaptureSource)
        assert adapter.packet_source.interface.name == "tnnl"
        assert adapter.packet_source.bpf_filter == "ip"
        assert adapter.packet_source.is_running is True

        # Pipeline stats check
        stats = adapter.get_pipeline_stats()
        assert stats["status"] == "active"
        assert stats["active_workers"] == 2
        assert stats["active_prevention"] is False
        assert "packet_source" in stats
        assert stats["packet_source"]["is_running"] is True

        # ML status check
        ml_stat = adapter.get_ml_status()
        assert ml_stat["status"] == "operational"
        assert ml_stat["enabled"] is True
        assert ml_stat["rf_loaded"] is True
        assert ml_stat["if_loaded"] is True
    finally:
        shutdown_pipeline(adapter)
        assert adapter.packet_source.is_running is False
        assert adapter.worker_pool.stats.active_workers == 0


def test_fastapi_backend_startup_and_health_endpoints(monkeypatch):
    """
    Verifies that starting the FastAPI application with lifespan initializes the DPI pipeline,
    exposing operational status on health, stats, ml, and firewall routes.
    """
    monkeypatch.setenv("DPI_INGESTION_MODE", "live")
    monkeypatch.setenv("DPI_INTERFACE", "tnnl")
    monkeypatch.setenv("DPI_BPF_FILTER", "ip")
    monkeypatch.setenv("DPI_ACTIVE_PREVENTION", "false")
    monkeypatch.setenv("ML_ENABLED", "true")
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    async def _async_test():
        app = create_app()
        async with lifespan(app):
            container = get_service_container()

            # 1. Health route check
            health_data = check_health(
                pipeline_adapter=container.pipeline_adapter,
                notification_mgr=container.notification_manager,
            )
            assert health_data.api_status == "operational"
            assert health_data.version == "1.0.0"

            # DPI Pipeline Subsystem
            dpi_status = health_data.dpi_pipeline
            assert dpi_status.status == "active"
            assert dpi_status.operational is True
            assert dpi_status.details is not None
            assert dpi_status.details["active_workers"] > 0
            assert dpi_status.details.get("packet_source") == "Tunnel[tnnl]"
            assert dpi_status.details.get("capture_running") is True

            # ML Runtime Subsystem
            ml_status = health_data.ml_runtime
            assert ml_status.status == "operational"
            assert ml_status.operational is True
            assert ml_status.details["enabled"] is True
            assert ml_status.details["rf_loaded"] is True
            assert ml_status.details["if_loaded"] is True

            # Email Notification Subsystem (kept disabled by default)
            email_status = health_data.email_notification
            assert email_status.status == "disabled"
            assert email_status.operational is False

            # 2. Stats route check
            stats_data = get_aggregate_statistics(pipeline_adapter=container.pipeline_adapter)
            assert stats_data.pipeline_status == "active"
            assert stats_data.active_workers > 0
            assert stats_data.active_prevention is False
            assert stats_data.total_packets_processed >= 0
            assert stats_data.total_flows >= 0

            # 3. ML status route check
            ml_data = get_ml_status(ml_service=container.ml_service)
            assert ml_data.status == "operational"
            assert ml_data.enabled is True
            assert ml_data.random_forest_loaded is True
            assert ml_data.isolation_forest_loaded is True

            # 4. Firewall rules check
            fw_rules = list_firewall_rules(firewall_service=container.firewall_service)
            assert fw_rules.active_prevention_enabled is False

        # After exiting lifespan context manager, graceful shutdown should have run
        if container.pipeline_adapter and container.pipeline_adapter.worker_pool:
            assert container.pipeline_adapter.worker_pool.stats.active_workers == 0
        if container.pipeline_adapter and container.pipeline_adapter.packet_source:
            assert container.pipeline_adapter.packet_source.is_running is False

    asyncio.run(_async_test())
