"""Integrations package exposing adapters to the DPI/IDS/IPS pipeline."""

from backend.integrations.dpi_adapter import DPIAdapter
from backend.integrations.firewall_adapter import FirewallAdapter
from backend.integrations.pipeline_adapter import PipelineAdapter
from backend.integrations.pipeline_factory import PipelineConfig, create_pipeline, shutdown_pipeline

__all__ = ["PipelineAdapter", "DPIAdapter", "FirewallAdapter", "PipelineConfig", "create_pipeline", "shutdown_pipeline"]

