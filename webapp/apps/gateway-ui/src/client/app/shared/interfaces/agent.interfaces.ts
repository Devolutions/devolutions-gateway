/**
 * WireGuard Agent Information
 */
export interface AgentInfo {
  agent_id: string;
  name: string;
  status: AgentStatus;
  assigned_ip: string;
  advertised_subnets: string[];
  route_epoch?: number;
  active_streams: number;
  /** Unix timestamp (seconds since epoch) */
  last_advertised_at?: number;
}

/**
 * Agent status enum
 */
export type AgentStatus = 'online' | 'offline' | 'unknown';

/**
 * Response from listing all agents
 */
export interface AgentsResponse {
  agents: AgentInfo[];
}

