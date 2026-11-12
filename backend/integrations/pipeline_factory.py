"""Pipeline Factory for constructing and initializing the DPI/IDS/IPS pipeline and packet ingestion."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
from typing import Dict, List, Optional

from capture.interface_manager import InterfaceManager
from ml.runtime.config import MLRuntimeConfig
from models.packet_models import InterfaceInfo
from server.client_manager import ClientManager
from server.ingestion import LiveCaptureSource, PacketSource, PcapReplaySource, TunnelCaptureSource
from server.wireguard_manager import WireGuardManager
from server.worker_pool import PipelineWorkerPool
from backend.integrations.pipeline_adapter import PipelineAdapter

logger = logging.getLogger("dpi_ids_ips.backend.pipeline_factory")


@dataclass
class PipelineConfig:
    """Configuration options for DPI Pipeline runtime."""
    ingestion_mode: str = "live"  # 'live', 'tunnel', 'pcap', 'disabled'
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    pcap_path: Optional[str] = None
    pcap_rate: str = "fastest"
    workers: int = 4
    queue_size: int = 10000
    active_prevention: bool = False
    ml_enabled: bool = True
    ml_artifacts_dir: str = "ml/artifacts"
    vpn_subnets: List[str] = field(default_factory=lambda: ["10.100.0.0/24", "10.8.0.0/24", "10.10.0.0/24"])
    wireguard_peers_file: Optional[str] = "wireguard_config/wireguard_peers.json"
    threat_intel_feeds: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> PipelineConfig:
        """Loads configuration from environment variables."""
        ingest_mode = os.getenv("DPI_INGESTION_MODE", "live").strip().lower()
        iface = os.getenv("DPI_INTERFACE", "").strip() or None
        bpf = os.getenv("DPI_BPF_FILTER", "").strip() or None
        pcap_path = os.getenv("DPI_PCAP_PATH", "").strip() or None
        pcap_rate = os.getenv("DPI_PCAP_RATE", "fastest").strip().lower()
        workers = int(os.getenv("DPI_WORKERS", "4").strip() or "4")
        queue_size = int(os.getenv("DPI_QUEUE_SIZE", "10000").strip() or "10000")
        active_prevention = os.getenv("DPI_ACTIVE_PREVENTION", "false").strip().lower() in ("true", "1", "yes")
        ml_enabled = os.getenv("ML_ENABLED", "true").strip().lower() in ("true", "1", "yes")
        ml_artifacts = os.getenv("ML_ARTIFACTS_DIR", "ml/artifacts").strip()

        subnets_raw = os.getenv("DPI_VPN_SUBNETS", "10.100.0.0/24,10.8.0.0/24,10.10.0.0/24").strip()
        subnets = [s.strip() for s in subnets_raw.split(",") if s.strip()]

        peers_file = os.getenv("DPI_WIREGUARD_PEERS_FILE", "wireguard_config/wireguard_peers.json").strip() or None

        feeds_raw = os.getenv("DPI_THREAT_INTEL_FEEDS", "").strip()
        feeds = [f.strip() for f in feeds_raw.split(",") if f.strip()]

        return cls(
            ingestion_mode=ingest_mode,
            interface=iface,
            bpf_filter=bpf,
            pcap_path=pcap_path,
            pcap_rate=pcap_rate,
            workers=workers,
            queue_size=queue_size,
            active_prevention=active_prevention,
            ml_enabled=ml_enabled,
            ml_artifacts_dir=ml_artifacts,
            vpn_subnets=subnets,
            wireguard_peers_file=peers_file,
            threat_intel_feeds=feeds,
        )


def _build_packet_source(config: PipelineConfig) -> Optional[PacketSource]:
    """Instantiates modular packet ingestion source according to config."""
    # A. PCAP Replay Mode
    if config.ingestion_mode == "pcap":
        pcap_file = config.pcap_path or "sample_vpn_traffic.pcap"
        if not os.path.exists(pcap_file):
            logger.error(f"Configured PCAP file does not exist: {pcap_file}")
            return None
        logger.info(f"Configured PCAP Replay source: {pcap_file} (Rate: {config.pcap_rate})")
        return PcapReplaySource(
            pcap_path=pcap_file,
            rate=config.pcap_rate,
        )

    # B. Live or Tunnel Capture Mode
    try:
        interfaces = InterfaceManager.get_interfaces()
    except Exception as e:
        logger.error(f"Failed to enumerate network interfaces: {e}")
        return None

    if not interfaces:
        logger.warning("No network interfaces detected. Check Npcap installation.")
        return None

    selected_iface: Optional[InterfaceInfo] = None

    # If specific interface requested
    if config.interface:
        try:
            selected_iface = InterfaceManager.select_interface(
                interfaces=interfaces,
                choice_input=config.interface,
            )
            logger.info(f"Selected interface '{selected_iface.name}' matching request '{config.interface}'.")
        except ValueError as err:
            logger.warning(f"Requested interface '{config.interface}' not found: {err}. Searching for fallback.")

    # Fallback if no specific interface or not found
    if not selected_iface:
        if config.ingestion_mode == "tunnel":
            selected_iface = InterfaceManager.find_tunnel_interface(interfaces)
            if selected_iface:
                logger.info(f"Auto-selected WireGuard/Wintun tunnel adapter: {selected_iface.name}")
        if not selected_iface:
            selected_iface = (
                InterfaceManager.find_tunnel_interface(interfaces)
                or InterfaceManager.find_wifi_interface(interfaces)
                or interfaces[0]
            )
            logger.info(f"Fallback selected interface: {selected_iface.name}")

    # Build appropriate capture source
    if config.ingestion_mode == "tunnel" or selected_iface.is_tunnel:
        logger.info(
            f"Instantiating TunnelCaptureSource on '{selected_iface.name}' "
            f"(IPs: {selected_iface.ipv4_addrs}, Filter: {config.bpf_filter})"
        )
        return TunnelCaptureSource(
            interface=selected_iface,
            bpf_filter=config.bpf_filter,
        )

    logger.info(
        f"Instantiating LiveCaptureSource on '{selected_iface.name}' "
        f"(IPs: {selected_iface.ipv4_addrs}, Filter: {config.bpf_filter})"
    )
    return LiveCaptureSource(
        interface=selected_iface,
        bpf_filter=config.bpf_filter,
    )


def create_pipeline(config: Optional[PipelineConfig] = None) -> PipelineAdapter:
    """Builds, starts, and returns an initialized PipelineAdapter."""
    if config is None:
        config = PipelineConfig.from_env()

    if config.ingestion_mode in ("disabled", "none", "off"):
        logger.info(f"DPI Ingestion mode is '{config.ingestion_mode}'. Pipeline will remain uninitialized.")
        return PipelineAdapter()

    # Pre-load peers mapping from wireguard_peers.json if present
    predefined_clients: Dict[str, str] = {}
    if config.wireguard_peers_file and os.path.exists(config.wireguard_peers_file):
        loaded_peers = WireGuardManager.load_peers_mapping(config.wireguard_peers_file)
        predefined_clients.update(loaded_peers)
        logger.info(f"Loaded {len(loaded_peers)} registered WireGuard client peers from {config.wireguard_peers_file}")

    # 1. Multi-Client Manager
    client_manager = ClientManager(
        vpn_subnets=config.vpn_subnets,
        predefined_clients=predefined_clients,
    )

    # 2. ML Runtime Config
    ml_config = MLRuntimeConfig(
        enabled=config.ml_enabled,
        artifacts_dir=config.ml_artifacts_dir,
    )

    # 3. Worker Pool with bounded queue
    worker_pool = PipelineWorkerPool(
        client_manager=client_manager,
        num_workers=config.workers,
        queue_size=config.queue_size,
        active_prevention=config.active_prevention,
        threat_intel_feeds=config.threat_intel_feeds,
        ml_config=ml_config,
    )

    # 4. Resolve Packet Source
    source = _build_packet_source(config)

    # 5. Start Subsystems
    worker_pool.start()
    if source is not None:
        source.start(worker_pool.packet_queue)
        logger.info(f"Packet ingestion started with source: {source.name}")
    else:
        logger.warning("No packet capture source active; worker pool is running in standby.")

    adapter = PipelineAdapter(
        worker_pool=worker_pool,
        client_manager=client_manager,
        packet_source=source,
    )
    logger.info(
        f"DPI Pipeline successfully initialized and started "
        f"(Workers: {config.workers}, Active Prevention: {config.active_prevention}, ML: {config.ml_enabled})."
    )
    return adapter


def shutdown_pipeline(adapter: PipelineAdapter) -> None:
    """Gracefully halts packet source and worker pool."""
    if adapter.packet_source and adapter.packet_source.is_running:
        logger.info(f"Stopping packet source: {adapter.packet_source.name}...")
        try:
            adapter.packet_source.stop()
        except Exception as e:
            logger.error(f"Error stopping packet source: {e}")

    if adapter.worker_pool:
        logger.info("Stopping worker pool...")
        try:
            adapter.worker_pool.stop()
        except Exception as e:
            logger.error(f"Error stopping worker pool: {e}")
