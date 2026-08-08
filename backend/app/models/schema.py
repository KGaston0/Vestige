from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class NodeType(str, Enum):
    HOST = "HOST"
    JUMPBOX = "JUMPBOX"
    SUBNET_GATEWAY = "SUBNET_GATEWAY"
    USER_ACCOUNT = "USER_ACCOUNT"
    URL = "URL"
    WEB_SERVER = "WEB_SERVER"
    SUPER_NODE = "SUPER_NODE"

class EdgeType(str, Enum):
    SSH_AUTH = "SSH_AUTH"
    HTTP_REQUEST = "HTTP_REQUEST"

class AnomalyFlag(str, Enum):
    HIGH_FREQUENCY_COLLAPSED = "HIGH_FREQUENCY_COLLAPSED"
    OFF_HOURS_ACCESS = "OFF_HOURS_ACCESS"
    RARE_PIVOT_PATH = "RARE_PIVOT_PATH"
    BRUTE_FORCE_BURST = "BRUTE_FORCE_BURST"
    PRIVILEGE_PIVOT = "PRIVILEGE_PIVOT"
    WEB_EXPLOIT_POST = "WEB_EXPLOIT_POST"
    HTTP_4XX_SCAN = "HTTP_4XX_SCAN"
    SSH_PRIVILEGE_PIVOT = "SSH_PRIVILEGE_PIVOT"
    FULL_ATTACK_CHAIN = "FULL_ATTACK_CHAIN"

class NodeModel(BaseModel):
    id: str = Field(..., description="Unique Identifier (e.g., host:10.0.0.1 or url:/api/upload)")
    label: str = Field(..., description="Human readable label")
    node_type: NodeType
    in_degree: int = 0
    out_degree: int = 0
    risk_score: float = 0.0
    x: float = 0.0
    y: float = 0.0
    size: float = 10.0
    color: str = "#3B82F6"
    metadata: Dict[str, Any] = Field(default_factory=dict)

class EdgeModel(BaseModel):
    id: str = Field(..., description="Unique edge identifier")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    edge_type: EdgeType = EdgeType.SSH_AUTH
    weight: float = 1.0
    total_attempts: int = 1
    http_verb: Optional[str] = None
    status_code: Optional[int] = None
    uri_path: Optional[str] = None
    successful_auths: Optional[int] = 0
    failed_auths: Optional[int] = 0
    distinct_users: List[str] = Field(default_factory=list)
    is_anomalous: bool = False
    anomaly_flags: List[AnomalyFlag] = Field(default_factory=list)
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    size: float = 2.0
    color: str = "#94A3B8"
    style: str = "solid"

class GraphData(BaseModel):
    nodes: List[NodeModel]
    edges: List[EdgeModel]

class TimelineBucket(BaseModel):
    bucket_start: str
    event_count: int
    failed_count: int

class SessionMeta(BaseModel):
    session_id: str
    timestamp: str
    log_filename: str
    total_lines_parsed: int
    valid_ssh_events: int
    valid_http_events: int = 0
    processing_time_ms: float
    noise_reduction_ratio: float

class SummaryData(BaseModel):
    total_nodes: int
    total_edges: int
    anomalous_edges_count: int
    high_risk_nodes_count: int
    detected_lateral_chains: int

class PresentationPayload(BaseModel):
    meta: SessionMeta
    summary: SummaryData
    graph: GraphData
    timeline: List[TimelineBucket] = Field(default_factory=list)

class StreamChunkPayload(BaseModel):
    chunk_index: int
    total_chunks: int
    processed_lines: int
    total_lines: int
    progress: float
    nodes: List[NodeModel]
    edges: List[EdgeModel]
    summary: SummaryData
    is_final: bool = False
    meta: Optional[SessionMeta] = None


class SuperNodeModel(NodeModel):
    """A super-node representing a cluster of individual nodes."""
    child_count: int = 0
    child_node_ids: List[str] = Field(default_factory=list)
    cluster_rule: str = ""
    is_expanded: bool = False


class ExpandResponse(BaseModel):
    """Response payload for drill-down expansion of a super-node."""
    parent_super_node_id: str
    nodes: List[NodeModel]
    edges: List[EdgeModel]


