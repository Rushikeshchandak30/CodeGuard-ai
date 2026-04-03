import { useState, useEffect, useCallback } from 'react';
import {
  Shield, AlertTriangle, Package, Users, TrendingUp,
  Activity, Bot, RefreshCw, ChevronRight, Clock,
  XCircle, CheckCircle, BarChart3,
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { api, OverviewData, TrendsData, TopPackagesData, AgentStatsData } from './api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Tab = 'overview' | 'trends' | 'packages' | 'agents' | 'developers';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const CHART_COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b', '#6366f1'];

// ---------------------------------------------------------------------------
// Stat Card
// ---------------------------------------------------------------------------

function StatCard({ icon: Icon, label, value, sub, color }: {
  icon: typeof Shield; label: string; value: string | number; sub?: string; color: string;
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5 backdrop-blur">
      <div className="flex items-center gap-3 mb-3">
        <div className={`rounded-lg p-2 ${color}`}>
          <Icon size={20} className="text-white" />
        </div>
        <span className="text-sm text-gray-400">{label}</span>
      </div>
      <div className="text-3xl font-bold text-white">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      {sub && <div className="text-xs text-gray-500 mt-1">{sub}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severity Badge
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-900/50 text-red-300 border-red-700',
    high: 'bg-orange-900/50 text-orange-300 border-orange-700',
    medium: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    low: 'bg-green-900/50 text-green-300 border-green-700',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${colors[severity] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Overview Tab
// ---------------------------------------------------------------------------

function OverviewTab({ data, trends }: { data: OverviewData | null; trends: TrendsData | null }) {
  if (!data) return <LoadingState />;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard icon={Activity} label="Total Events" value={data.totals.events} color="bg-blue-600" />
        <StatCard icon={XCircle} label="Installs Blocked" value={data.totals.blocked} color="bg-red-600" />
        <StatCard icon={AlertTriangle} label="Hallucinations" value={data.totals.hallucinations} color="bg-orange-600" />
        <StatCard icon={Shield} label="Vulnerabilities" value={data.totals.vulnerabilities} color="bg-purple-600" />
        <StatCard icon={Users} label="Developers" value={data.totals.developers} color="bg-teal-600" />
        <StatCard icon={CheckCircle} label="Avg Trust Score" value={data.totals.avgTrustScore} sub="out of 100" color="bg-green-600" />
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={data.severityCounts} dataKey="count" nameKey="severity" cx="50%" cy="50%" outerRadius={90} label={({ severity, count }) => `${severity}: ${count}`}>
                {data.severityCounts.map((entry, i) => (
                  <Cell key={i} fill={SEVERITY_COLORS[entry.severity] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Daily Trend */}
        {trends && (
          <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
            <h3 className="text-sm font-medium text-gray-300 mb-4">Daily Activity (30 days)</h3>
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={trends.daily}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="day" tick={{ fill: '#9ca3af', fontSize: 11 }} tickFormatter={(v) => new Date(v).toLocaleDateString('en', { month: 'short', day: 'numeric' })} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
                <Area type="monotone" dataKey="total" stroke="#3b82f6" fill="#3b82f640" name="Total" />
                <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="#ef444440" name="Blocked" />
                <Area type="monotone" dataKey="hallucinations" stroke="#f97316" fill="#f9731640" name="Hallucinations" />
                <Legend />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Recent Events Table */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4">Recent Events</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4">Event</th>
                <th className="text-left py-2 pr-4">Package</th>
                <th className="text-left py-2 pr-4">Ecosystem</th>
                <th className="text-left py-2 pr-4">Severity</th>
                <th className="text-left py-2 pr-4">Action</th>
                <th className="text-left py-2">Time</th>
              </tr>
            </thead>
            <tbody>
              {data.recentEvents.map((ev, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-2 pr-4 text-gray-300">{ev.event_type.replace(/_/g, ' ')}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-blue-400">{ev.package_name}</td>
                  <td className="py-2 pr-4 text-gray-400">{ev.ecosystem}</td>
                  <td className="py-2 pr-4"><SeverityBadge severity={ev.severity} /></td>
                  <td className="py-2 pr-4 text-gray-400">{ev.action_taken}</td>
                  <td className="py-2 text-gray-500 text-xs">{new Date(ev.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Trends Tab
// ---------------------------------------------------------------------------

function TrendsTab({ data }: { data: TrendsData | null }) {
  if (!data) return <LoadingState />;

  // Group agent trends by agent
  const agents = [...new Set(data.agentTrends.map(t => t.agent))];

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4">Events Over Time</h3>
        <ResponsiveContainer width="100%" height={320}>
          <AreaChart data={data.daily}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="day" tick={{ fill: '#9ca3af', fontSize: 11 }} tickFormatter={(v) => new Date(v).toLocaleDateString('en', { month: 'short', day: 'numeric' })} />
            <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
            <Area type="monotone" dataKey="total" stroke="#3b82f6" fill="#3b82f630" name="Total Events" />
            <Area type="monotone" dataKey="criticalHigh" stroke="#ef4444" fill="#ef444430" name="Critical/High" />
            <Area type="monotone" dataKey="blocked" stroke="#a855f7" fill="#a855f730" name="Blocked" />
            <Legend />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4">Hallucinations by AI Agent</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={data.daily}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="day" tick={{ fill: '#9ca3af', fontSize: 11 }} tickFormatter={(v) => new Date(v).toLocaleDateString('en', { month: 'short', day: 'numeric' })} />
            <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
            <Bar dataKey="hallucinations" fill="#f97316" name="Hallucinations" radius={[4, 4, 0, 0]} />
            <Legend />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {agents.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Agent Activity Comparison</h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((agent, idx) => {
              const agentData = data.agentTrends.filter(t => t.agent === agent);
              const totalEvents = agentData.reduce((s, d) => s + d.events, 0);
              const totalHalluc = agentData.reduce((s, d) => s + d.hallucinations, 0);
              return (
                <div key={agent} className="rounded-lg border border-gray-800 bg-gray-800/40 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Bot size={16} style={{ color: CHART_COLORS[idx % CHART_COLORS.length] }} />
                    <span className="font-medium text-gray-200">{agent}</span>
                  </div>
                  <div className="text-xs text-gray-400">
                    <span className="text-white font-medium">{totalEvents.toLocaleString()}</span> events,{' '}
                    <span className="text-orange-400 font-medium">{totalHalluc.toLocaleString()}</span> hallucinations
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Packages Tab
// ---------------------------------------------------------------------------

function PackagesTab({ data }: { data: TopPackagesData | null }) {
  if (!data) return <LoadingState />;

  return (
    <div className="space-y-6">
      {/* Top Vulnerable */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <AlertTriangle size={16} className="text-red-400" /> Most Vulnerable Packages
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4">Package</th>
                <th className="text-left py-2 pr-4">Ecosystem</th>
                <th className="text-left py-2 pr-4">Vulnerabilities</th>
                <th className="text-left py-2">Highest Severity</th>
              </tr>
            </thead>
            <tbody>
              {data.topVulnerable.map((pkg, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-2 pr-4 font-mono text-xs text-blue-400">{pkg.package_name}</td>
                  <td className="py-2 pr-4 text-gray-400">{pkg.ecosystem}</td>
                  <td className="py-2 pr-4 text-white font-medium">{pkg.vuln_count}</td>
                  <td className="py-2"><SeverityBadge severity={pkg.highest_severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.topVulnerable.length === 0 && <p className="text-gray-500 text-sm py-4 text-center">No vulnerable packages found.</p>}
        </div>
      </div>

      {/* Top Hallucinated */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <Package size={16} className="text-orange-400" /> Most Hallucinated Packages
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4">Package</th>
                <th className="text-left py-2 pr-4">Ecosystem</th>
                <th className="text-left py-2 pr-4">Reports</th>
                <th className="text-left py-2 pr-4">Risk</th>
                <th className="text-left py-2 pr-4">AI Agent</th>
                <th className="text-left py-2">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {data.topHallucinated.map((pkg, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-2 pr-4 font-mono text-xs text-orange-400">{pkg.package_name}</td>
                  <td className="py-2 pr-4 text-gray-400">{pkg.ecosystem}</td>
                  <td className="py-2 pr-4 text-white font-medium">{pkg.report_count}</td>
                  <td className="py-2 pr-4">
                    <div className="w-16 bg-gray-800 rounded-full h-2">
                      <div className="h-2 rounded-full" style={{ width: `${pkg.risk_score * 100}%`, background: pkg.risk_score > 0.7 ? '#ef4444' : pkg.risk_score > 0.4 ? '#eab308' : '#22c55e' }} />
                    </div>
                  </td>
                  <td className="py-2 pr-4 text-gray-400">{pkg.ai_agent || 'Unknown'}</td>
                  <td className="py-2 text-gray-500 text-xs">{new Date(pkg.last_seen).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.topHallucinated.length === 0 && <p className="text-gray-500 text-sm py-4 text-center">No hallucinated packages found.</p>}
        </div>
      </div>

      {/* Lowest Trust */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <Shield size={16} className="text-yellow-400" /> Lowest Trust Score Packages
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="text-left py-2 pr-4">Package</th>
                <th className="text-left py-2 pr-4">Ecosystem</th>
                <th className="text-left py-2 pr-4">Trust Score</th>
                <th className="text-left py-2 pr-4">Tier</th>
                <th className="text-left py-2 pr-4">Vulns</th>
                <th className="text-left py-2">Install Scripts</th>
              </tr>
            </thead>
            <tbody>
              {data.lowestTrust.map((pkg, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-2 pr-4 font-mono text-xs text-yellow-400">{pkg.package_name}</td>
                  <td className="py-2 pr-4 text-gray-400">{pkg.ecosystem}</td>
                  <td className="py-2 pr-4">
                    <span className={`font-medium ${pkg.trust_score < 30 ? 'text-red-400' : 'text-yellow-400'}`}>{pkg.trust_score}</span>
                    <span className="text-gray-500">/100</span>
                  </td>
                  <td className="py-2 pr-4">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${pkg.trust_tier === 'untrusted' ? 'bg-red-900/50 text-red-300' : 'bg-yellow-900/50 text-yellow-300'}`}>
                      {pkg.trust_tier}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-white">{pkg.vulnerability_count}</td>
                  <td className="py-2">
                    {pkg.has_install_scripts ? <span className="text-red-400 text-xs">Yes</span> : <span className="text-gray-500 text-xs">No</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.lowestTrust.length === 0 && <p className="text-gray-500 text-sm py-4 text-center">No suspicious packages found.</p>}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agents Tab
// ---------------------------------------------------------------------------

function AgentsTab({ data }: { data: AgentStatsData | null }) {
  if (!data) return <LoadingState />;

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
        <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
          <Bot size={16} className="text-blue-400" /> AI Agent Comparison
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={data.agents} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
            <YAxis type="category" dataKey="agent" tick={{ fill: '#9ca3af', fontSize: 11 }} width={140} />
            <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
            <Bar dataKey="hallucinations_reported" fill="#f97316" name="Hallucinations" radius={[0, 4, 4, 0]} />
            <Bar dataKey="installs_blocked" fill="#ef4444" name="Blocked" radius={[0, 4, 4, 0]} />
            <Legend />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Agent Cards */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Agent Details</h3>
          <div className="space-y-3">
            {data.agents.map((agent, i) => (
              <div key={i} className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-800/40 p-3">
                <div className="flex items-center gap-3">
                  <Bot size={18} style={{ color: CHART_COLORS[i % CHART_COLORS.length] }} />
                  <div>
                    <div className="font-medium text-gray-200">{agent.agent}</div>
                    <div className="text-xs text-gray-500">Top ecosystem: {agent.top_ecosystem}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-orange-400 text-sm font-medium">{agent.hallucinations_reported} halluc.</div>
                  <div className="text-red-400 text-xs">{agent.installs_blocked} blocked</div>
                </div>
              </div>
            ))}
            {data.agents.length === 0 && <p className="text-gray-500 text-sm text-center py-4">No agent data yet.</p>}
          </div>
        </div>

        {/* IDE Usage */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">IDE Usage</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={data.ides} dataKey="total_events" nameKey="ide" cx="50%" cy="50%" outerRadius={90} label={({ ide, total_events }) => `${ide}: ${total_events}`}>
                {data.ides.map((_, i) => (
                  <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Developers Tab
// ---------------------------------------------------------------------------

function DevelopersTab() {
  const [devs, setDevs] = useState<Array<{
    id: string; totalEvents: number; hallucinations: number;
    blocked: number; criticalHigh: number; lastActive: string;
  }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getDevelopers().then(d => { setDevs(d.developers); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState />;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
      <h3 className="text-sm font-medium text-gray-300 mb-4 flex items-center gap-2">
        <Users size={16} className="text-teal-400" /> Developer Activity (Anonymized)
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400">
              <th className="text-left py-2 pr-4">Developer ID</th>
              <th className="text-left py-2 pr-4">Events</th>
              <th className="text-left py-2 pr-4">Hallucinations</th>
              <th className="text-left py-2 pr-4">Blocked</th>
              <th className="text-left py-2 pr-4">Critical/High</th>
              <th className="text-left py-2">Last Active</th>
            </tr>
          </thead>
          <tbody>
            {devs.map((d, i) => (
              <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="py-2 pr-4 font-mono text-xs text-gray-400">{d.id?.slice(0, 12)}...</td>
                <td className="py-2 pr-4 text-white">{d.totalEvents}</td>
                <td className="py-2 pr-4 text-orange-400">{d.hallucinations}</td>
                <td className="py-2 pr-4 text-red-400">{d.blocked}</td>
                <td className="py-2 pr-4 text-yellow-400">{d.criticalHigh}</td>
                <td className="py-2 text-gray-500 text-xs flex items-center gap-1">
                  <Clock size={12} /> {new Date(d.lastActive).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {devs.length === 0 && <p className="text-gray-500 text-sm py-4 text-center">No developer data yet. Enable telemetry in CodeGuard AI settings.</p>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading State
// ---------------------------------------------------------------------------

function LoadingState() {
  return (
    <div className="flex items-center justify-center py-20">
      <RefreshCw size={24} className="animate-spin text-blue-400 mr-3" />
      <span className="text-gray-400">Loading data...</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export default function App() {
  const [tab, setTab] = useState<Tab>('overview');
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [trends, setTrends] = useState<TrendsData | null>(null);
  const [packages, setPackages] = useState<TopPackagesData | null>(null);
  const [agents, setAgents] = useState<AgentStatsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setError(null);
    try {
      const [ov, tr, pk, ag] = await Promise.allSettled([
        api.getOverview(),
        api.getTrends(),
        api.getTopPackages(),
        api.getAgentStats(),
      ]);
      if (ov.status === 'fulfilled') setOverview(ov.value);
      if (tr.status === 'fulfilled') setTrends(tr.value);
      if (pk.status === 'fulfilled') setPackages(pk.value);
      if (ag.status === 'fulfilled') setAgents(ag.value);
    } catch {
      setError('Failed to load dashboard data. Is the GHIN API running?');
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const tabs: Array<{ id: Tab; label: string; icon: typeof Shield }> = [
    { id: 'overview', label: 'Overview', icon: BarChart3 },
    { id: 'trends', label: 'Trends', icon: TrendingUp },
    { id: 'packages', label: 'Packages', icon: Package },
    { id: 'agents', label: 'AI Agents', icon: Bot },
    { id: 'developers', label: 'Developers', icon: Users },
  ];

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield size={28} className="text-blue-500" />
            <div>
              <h1 className="text-lg font-bold text-white">CodeGuard AI</h1>
              <p className="text-xs text-gray-500">Team Security Dashboard</p>
            </div>
          </div>
          <button
            onClick={loadData}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm transition"
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Tab Navigation */}
        <nav className="flex gap-1 mb-6 border-b border-gray-800 pb-px overflow-x-auto">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg transition whitespace-nowrap ${
                tab === id
                  ? 'bg-gray-800 text-white border-b-2 border-blue-500'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
              }`}
            >
              <Icon size={16} />
              {label}
              <ChevronRight size={12} className={tab === id ? 'text-blue-400' : 'text-gray-600'} />
            </button>
          ))}
        </nav>

        {/* Error */}
        {error && (
          <div className="mb-6 rounded-lg bg-red-900/30 border border-red-800 p-4 text-red-300 text-sm">
            {error}
          </div>
        )}

        {/* Content */}
        {tab === 'overview' && <OverviewTab data={overview} trends={trends} />}
        {tab === 'trends' && <TrendsTab data={trends} />}
        {tab === 'packages' && <PackagesTab data={packages} />}
        {tab === 'agents' && <AgentsTab data={agents} />}
        {tab === 'developers' && <DevelopersTab />}
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between text-xs text-gray-600">
          <span>CodeGuard AI v5.2.0 Team Dashboard</span>
          <span>Data from GHIN (Global Hallucination Intelligence Network)</span>
        </div>
      </footer>
    </div>
  );
}
