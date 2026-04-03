const BASE = '/api/v1';

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) { throw new Error(`API error: ${res.status}`); }
  return res.json();
}

export interface OverviewData {
  totals: {
    events: number;
    blocked: number;
    hallucinations: number;
    vulnerabilities: number;
    developers: number;
    avgTrustScore: number;
  };
  severityCounts: Array<{ severity: string; count: number }>;
  recentEvents: Array<{
    event_type: string;
    package_name: string;
    ecosystem: string;
    severity: string;
    action_taken: string;
    created_at: string;
  }>;
}

export interface TrendsData {
  daily: Array<{
    day: string;
    total: number;
    hallucinations: number;
    blocked: number;
    criticalHigh: number;
  }>;
  agentTrends: Array<{
    agent: string;
    day: string;
    events: number;
    hallucinations: number;
  }>;
}

export interface TopPackagesData {
  topVulnerable: Array<{
    package_name: string;
    ecosystem: string;
    vuln_count: number;
    highest_severity: string;
  }>;
  topHallucinated: Array<{
    package_name: string;
    ecosystem: string;
    report_count: number;
    risk_score: number;
    ai_agent: string;
    first_seen: string;
    last_seen: string;
  }>;
  lowestTrust: Array<{
    package_name: string;
    ecosystem: string;
    trust_score: number;
    trust_tier: string;
    vulnerability_count: number;
    has_install_scripts: boolean;
  }>;
}

export interface AgentStatsData {
  agents: Array<{
    agent: string;
    hallucinations_reported: number;
    installs_blocked: number;
    top_ecosystem: string;
  }>;
  ides: Array<{
    ide: string;
    total_events: number;
    blocked: number;
  }>;
}

export interface DeveloperData {
  developers: Array<{
    id: string;
    totalEvents: number;
    hallucinations: number;
    blocked: number;
    criticalHigh: number;
    lastActive: string;
  }>;
}

export const api = {
  getOverview: () => fetchJson<OverviewData>('/dashboard/overview'),
  getTrends: (days = 30) => fetchJson<TrendsData>(`/dashboard/trends?days=${days}`),
  getTopPackages: (limit = 20) => fetchJson<TopPackagesData>(`/dashboard/top-packages?limit=${limit}`),
  getAgentStats: () => fetchJson<AgentStatsData>('/stats/agents'),
  getDevelopers: () => fetchJson<DeveloperData>('/dashboard/developers'),
};
