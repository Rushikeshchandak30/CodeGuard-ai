import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield, Users, Scan, Database, Activity, Server,
  Zap, ToggleLeft, ToggleRight, RefreshCw, AlertTriangle,
  TrendingUp, Package, ChevronRight, LogOut, Crown,
} from 'lucide-react';
import { adminApi } from '../lib/api';
import { useAuthStore } from '../store/auth';
import { useNavigate } from 'react-router-dom';

// ─── Types ───────────────────────────────────────────────────────────

interface SystemStats {
  system: {
    users: number;
    teams: number;
    scans: number;
    scansLast24h: number;
    activeApiKeys: number;
  };
  ghin: {
    totalPackages: number;
    totalReports: number;
    topReported: Array<{ packageName: string; ecosystem: string; status: string; reportCount: number }>;
  };
  featureFlags: Record<string, boolean>;
  server: {
    uptime: number;
    memoryUsage: { heapUsed: number; heapTotal: number; rss: number };
    nodeVersion: string;
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function formatBytes(bytes: number): string {
  return `${Math.round(bytes / 1024 / 1024)} MB`;
}

// ─── Sub-components ───────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color = 'indigo' }: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
}) {
  const colors: Record<string, string> = {
    indigo: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
    amber:  'bg-amber-500/10  text-amber-400  border-amber-500/20',
    green:  'bg-green-500/10  text-green-400  border-green-500/20',
    blue:   'bg-blue-500/10   text-blue-400   border-blue-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    red:    'bg-red-500/10    text-red-400    border-red-500/20',
  };
  return (
    <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4">
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-8 h-8 rounded-lg border flex items-center justify-center ${colors[color]}`}>
          <Icon className="w-4 h-4" />
        </div>
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────

export default function AdminDashboard() {
  const navigate = useNavigate();
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const user = useAuthStore((s) => s.user);
  const qc = useQueryClient();
  const [consolidating, setConsolidating] = useState(false);
  const [flagMessage, setFlagMessage] = useState('');

  const { data, isLoading, isError, refetch } = useQuery<SystemStats>({
    queryKey: ['admin-stats'],
    queryFn: () => adminApi.stats().then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: flagsData } = useQuery<{ flags: Record<string, boolean> }>({
    queryKey: ['admin-flags'],
    queryFn: () => adminApi.flags().then((r) => r.data),
  });

  const setFlagMutation = useMutation({
    mutationFn: ({ flag, value }: { flag: string; value: boolean }) =>
      adminApi.setFlag(flag, value),
    onSuccess: (_, vars) => {
      setFlagMessage(`Flag "${vars.flag}" set to ${vars.value}`);
      qc.invalidateQueries({ queryKey: ['admin-flags'] });
      setTimeout(() => setFlagMessage(''), 3000);
    },
  });

  async function handleConsolidate() {
    setConsolidating(true);
    try {
      await adminApi.consolidate();
      await refetch();
    } finally {
      setConsolidating(false);
    }
  }

  function handleLogout() {
    clearAuth();
    navigate('/login');
  }

  const flags = flagsData?.flags ?? data?.featureFlags ?? {};

  return (
    <div className="min-h-screen bg-[#0f1117] text-white">
      {/* Top bar */}
      <header className="border-b border-[#2a2d3e] bg-[#1a1d27] px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-amber-500/20 border border-amber-500/30 flex items-center justify-center">
            <Crown className="w-4 h-4 text-amber-400" />
          </div>
          <div>
            <h1 className="text-sm font-semibold text-white">Admin Dashboard</h1>
            <p className="text-[11px] text-gray-500">CodeGuard AI — System Overview</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 hidden sm:block">{user?.email}</span>
          <span className="text-[10px] bg-amber-500/20 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded-full font-medium">
            ADMIN
          </span>
          <button
            onClick={() => refetch()}
            title="Refresh"
            className="p-1.5 text-gray-500 hover:text-white transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-red-400 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out
          </button>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {isLoading && (
          <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
            Loading system stats…
          </div>
        )}

        {isError && (
          <div className="flex items-center gap-2 text-red-400 bg-red-400/10 border border-red-400/20 rounded-xl p-4 text-sm">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            Failed to load admin stats. Check that the backend is running and your session is valid.
          </div>
        )}

        {data && (
          <>
            {/* ─── System Stats ─── */}
            <section>
              <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                System
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                <StatCard icon={Users}    label="Total Users"       value={data.system.users}        color="indigo" />
                <StatCard icon={Shield}   label="Total Scans"       value={data.system.scans}        color="green"  />
                <StatCard icon={TrendingUp} label="Scans (24h)"     value={data.system.scansLast24h} color="blue"   />
                <StatCard icon={Server}   label="Teams"             value={data.system.teams}        color="purple" />
                <StatCard icon={Zap}      label="Active API Keys"   value={data.system.activeApiKeys} color="amber" />
              </div>
            </section>

            {/* ─── GHIN Stats ─── */}
            <section>
              <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                GHIN — Global Hallucination Intelligence Network
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
                <StatCard icon={Database} label="Total Packages"  value={data.ghin.totalPackages}  color="indigo" />
                <StatCard icon={Activity} label="Total Reports"   value={data.ghin.totalReports}   color="amber"  />
                <StatCard icon={Package}  label="Top Reported"    value={data.ghin.topReported[0]?.packageName ?? '—'}
                  sub={data.ghin.topReported[0] ? `${data.ghin.topReported[0].reportCount} reports` : undefined}
                  color="red" />
              </div>

              {data.ghin.topReported.length > 0 && (
                <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-[#2a2d3e] flex items-center justify-between">
                    <span className="text-xs font-medium text-gray-300">Top Reported Hallucinated Packages</span>
                    <button
                      onClick={handleConsolidate}
                      disabled={consolidating}
                      className="flex items-center gap-1.5 text-[11px] text-indigo-400 hover:text-indigo-300 disabled:opacity-50 transition-colors"
                    >
                      <RefreshCw className={`w-3 h-3 ${consolidating ? 'animate-spin' : ''}`} />
                      {consolidating ? 'Running…' : 'Run Consolidation'}
                    </button>
                  </div>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#2a2d3e]">
                        <th className="text-left px-4 py-2 text-gray-500 font-normal">Package</th>
                        <th className="text-left px-4 py-2 text-gray-500 font-normal">Ecosystem</th>
                        <th className="text-left px-4 py-2 text-gray-500 font-normal">Status</th>
                        <th className="text-right px-4 py-2 text-gray-500 font-normal">Reports</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.ghin.topReported.map((pkg, i) => (
                        <tr key={i} className="border-b border-[#1e2130] last:border-0 hover:bg-[#1e2130] transition-colors">
                          <td className="px-4 py-2.5 font-mono text-white">{pkg.packageName}</td>
                          <td className="px-4 py-2.5 text-gray-400">{pkg.ecosystem}</td>
                          <td className="px-4 py-2.5">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                              pkg.status === 'CONFIRMED' ? 'bg-red-500/20 text-red-400' :
                              pkg.status === 'REPORTED'  ? 'bg-amber-500/20 text-amber-400' :
                              'bg-gray-500/20 text-gray-400'
                            }`}>
                              {pkg.status}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-right text-gray-300">{pkg.reportCount}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            {/* ─── Feature Flags ─── */}
            <section>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Feature Flags
                </h2>
                {flagMessage && (
                  <span className="text-[11px] text-green-400 bg-green-400/10 border border-green-400/20 px-2 py-0.5 rounded-full">
                    ✓ {flagMessage}
                  </span>
                )}
              </div>
              <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl divide-y divide-[#2a2d3e]">
                {Object.entries(flags).map(([flag, value]) => (
                  <div key={flag} className="flex items-center justify-between px-4 py-3">
                    <div>
                      <p className="text-xs font-mono text-gray-200">{flag}</p>
                      <p className="text-[11px] text-gray-500 mt-0.5">Runtime override</p>
                    </div>
                    <button
                      onClick={() => setFlagMutation.mutate({ flag, value: !value })}
                      className={`flex items-center gap-1.5 text-xs font-medium transition-colors ${
                        value ? 'text-green-400 hover:text-green-300' : 'text-gray-500 hover:text-gray-400'
                      }`}
                    >
                      {value
                        ? <ToggleRight className="w-5 h-5" />
                        : <ToggleLeft  className="w-5 h-5" />
                      }
                      {value ? 'ON' : 'OFF'}
                    </button>
                  </div>
                ))}
                {Object.keys(flags).length === 0 && (
                  <p className="px-4 py-4 text-xs text-gray-500">No feature flags available.</p>
                )}
              </div>
            </section>

            {/* ─── Server Info ─── */}
            <section>
              <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Server
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <StatCard
                  icon={Activity}
                  label="Uptime"
                  value={formatUptime(data.server.uptime)}
                  color="green"
                />
                <StatCard
                  icon={Server}
                  label="Heap Used"
                  value={formatBytes(data.server.memoryUsage.heapUsed)}
                  sub={`of ${formatBytes(data.server.memoryUsage.heapTotal)} total`}
                  color="blue"
                />
                <StatCard
                  icon={Zap}
                  label="Node.js"
                  value={data.server.nodeVersion}
                  color="purple"
                />
              </div>
            </section>

            {/* ─── Quick Links ─── */}
            <section>
              <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Navigation
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Security Dashboard', path: '/',       icon: Shield  },
                  { label: 'Scan History',        path: '/scans',  icon: Scan    },
                  { label: 'GHIN Packages',       path: '/ghin',   icon: Database },
                  { label: 'Teams',               path: '/teams',  icon: Users   },
                ].map(({ label, path, icon: Icon }) => (
                  <button
                    key={path}
                    onClick={() => navigate(path)}
                    className="flex items-center justify-between bg-[#1a1d27] border border-[#2a2d3e] hover:border-indigo-500/40 rounded-xl px-4 py-3 text-xs text-gray-300 hover:text-white transition-all group"
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="w-3.5 h-3.5 text-gray-500 group-hover:text-indigo-400 transition-colors" />
                      {label}
                    </div>
                    <ChevronRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-indigo-400 transition-colors" />
                  </button>
                ))}
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
