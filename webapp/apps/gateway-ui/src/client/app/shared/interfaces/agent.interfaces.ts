export interface DomainInfo {
  domain: string;
  auto_detected: boolean;
}

export interface AgentInfo {
  agent_id: string;
  name: string;
  cert_fingerprint: string;
  is_online: boolean;
  last_seen_ms: number;
  subnets: string[];
  domains: DomainInfo[];
  route_epoch?: number;
}

export interface AgentEnrollmentStringRequest {
  api_base_url: string;
  quic_host?: string;
  name?: string;
  lifetime?: number;
}

export interface AgentEnrollmentStringResponse {
  enrollment_string: string;
  enrollment_command: string;
  quic_endpoint: string;
  expires_at_unix: number;
}
