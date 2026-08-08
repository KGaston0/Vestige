export type NodeType = 'HOST' | 'JUMPBOX' | 'SUBNET_GATEWAY' | 'USER_ACCOUNT' | 'URL' | 'WEB_SERVER' | 'SUPER_NODE';

export type EdgeType = 'SSH_AUTH' | 'HTTP_REQUEST';

export type AnomalyFlag =
  | 'HIGH_FREQUENCY_COLLAPSED'
  | 'OFF_HOURS_ACCESS'
  | 'RARE_PIVOT_PATH'
  | 'BRUTE_FORCE_BURST'
  | 'PRIVILEGE_PIVOT'
  | 'WEB_EXPLOIT_POST'
  | 'HTTP_4XX_SCAN'
  | 'SSH_PRIVILEGE_PIVOT'
  | 'FULL_ATTACK_CHAIN';

export interface NodeModel {
  id: string;
  label: string;
  node_type: NodeType;
  in_degree: number;
  out_degree: number;
  risk_score: number;
  x: number;
  y: number;
  size: number;
  color: string;
  metadata: Record<string, any>;
}

/** Super-Node: a cluster of individual nodes for hierarchical aggregation. */
export interface SuperNodeModel extends NodeModel {
  child_count: number;
  child_node_ids: string[];
  cluster_rule: string;
  is_expanded: boolean;
}

export interface EdgeModel {
  id: string;
  source: string;
  target: string;
  edge_type: EdgeType;
  weight: number;
  total_attempts: number;
  http_verb?: string;
  status_code?: number;
  uri_path?: string;
  successful_auths?: number;
  failed_auths?: number;
  distinct_users: string[];
  is_anomalous: boolean;
  anomaly_flags: AnomalyFlag[];
  first_timestamp?: string;
  last_timestamp?: string;
  size: number;
  color: string;
  style: 'solid' | 'dashed';
}

export interface GraphData {
  nodes: NodeModel[];
  edges: EdgeModel[];
}

export interface SessionMeta {
  session_id: string;
  timestamp: string;
  log_filename: string;
  total_lines_parsed: number;
  valid_ssh_events: number;
  valid_http_events: number;
  processing_time_ms: number;
  noise_reduction_ratio: number;
}

export interface SummaryData {
  total_nodes: number;
  total_edges: number;
  anomalous_edges_count: number;
  high_risk_nodes_count: number;
  detected_lateral_chains: number;
}

export interface PresentationPayload {
  meta: SessionMeta;
  summary: SummaryData;
  graph: GraphData;
}

export interface StreamChunkPayload {
  chunk_index: number;
  total_chunks: number;
  processed_lines: number;
  total_lines: number;
  progress: number;
  nodes: NodeModel[];
  edges: EdgeModel[];
  summary: SummaryData;
  is_final: boolean;
  meta?: SessionMeta;
}

export interface StreamingState {
  isStreaming: boolean;
  progress: number;
  processedLines: number;
  totalLines: number;
  currentChunk: number;
  totalChunks: number;
  statusText: string;
}

/** Response from the drill-down expansion endpoint. */
export interface ExpandResponse {
  parent_super_node_id: string;
  nodes: NodeModel[];
  edges: EdgeModel[];
}

/** Type guard: checks if a NodeModel is actually a SuperNodeModel. */
export function isSuperNode(node: NodeModel): node is SuperNodeModel {
  return node.node_type === 'SUPER_NODE' && 'child_count' in node;
}
