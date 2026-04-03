import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, AlertTriangle, ScanLine, Database, TrendingUp, TrendingDown } from 'lucide-react';
import { scansApi, ghinApi } from '../lib/api';
import { format } from 'date-fns';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

function StatCard({
  label, value, icon: Icon, trend, color
}: {
  label: string; value: string | number; icon: any;
  trend?: number; color: string;
}) {
  return (
    <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-gray-500">{label}</span>
        <div className={`p-1.5 rounded-lg ${color}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      {trend !== undefined && (
        <div className={`flex items-center gap-1 mt-1 text-xs ${trend >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
          {trend >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          {Math.abs(trend)}% vs last week
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const { data: trendsData } = useQuery({
    queryKey: ['scans-trends'],
    queryFn: () => scansApi.trends().then(r => r.data),
  });

  const { data: ghinStats } = useQuery({
    queryKey: ['ghin-stats'],
    queryFn: () => ghinApi.stats().then(r => r.data),
  });

  const { data: recentScans } = useQuery({
    queryKey: ['scans-recent'],
    queryFn: () => scansApi.list(1, 5).then(r => r.data),
  });

  const trends = trendsData?.trend || [];
  const totalScans = trendsData?.totalScans ?? 0;
  const avgScore = trendsData?.latestSecurityScore ?? 0;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Security Dashboard</h1>
        <p className="text-sm text-gray-500 mt-0.5">Real-time overview of your security posture</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Scans" value={totalScans} icon={ScanLine}
          color="bg-indigo-500/20 text-indigo-400" trend={12} />
        <StatCard label="Avg Security Score" value={`${avgScore}/100`} icon={ShieldCheck}
          color="bg-emerald-500/20 text-emerald-400" />
        <StatCard label="GHIN Packages" value={ghinStats?.totalPackages ?? 0} icon={Database}
          color="bg-amber-500/20 text-amber-400" />
        <StatCard label="Confirmed Hallucinations" value={ghinStats?.confirmedHallucinations ?? 0}
          icon={AlertTriangle} color="bg-red-500/20 text-red-400" />
      </div>

      {/* Chart */}
      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4 mb-6">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Findings Trend (30 days)</h2>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={trends}>
            <defs>
              <linearGradient id="gradFindings" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="date" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: '#1a1d27', border: '1px solid #2a2d3e', borderRadius: 8 }}
              labelStyle={{ color: '#9ca3af' }}
            />
            <Area type="monotone" dataKey="findings" stroke="#6366f1" fill="url(#gradFindings)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Recent scans */}
      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-[#2a2d3e]">
          <h2 className="text-sm font-semibold text-gray-300">Recent Scans</h2>
        </div>
        <div className="divide-y divide-[#2a2d3e]">
          {(recentScans?.scans || []).map((scan: any) => {
            const meta = scan.metadata || {};
            const summary = meta.summary || {};
            return (
            <div key={scan.id} className="px-4 py-3 flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-200 truncate">{meta.projectPath || 'Unknown'}</p>
                <p className="text-xs text-gray-500">{format(new Date(scan.startedAt), 'MMM d, HH:mm')} · {scan.scanType}</p>
              </div>
              <div className="text-right">
                <span className={`text-sm font-bold ${(meta.securityScore ?? 0) >= 80 ? 'text-emerald-400' : (meta.securityScore ?? 0) >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                  {meta.securityScore ?? '—'}/100
                </span>
                <p className="text-xs text-gray-500">{summary.totalFindings ?? 0} findings</p>
              </div>
            </div>
            );
          })}
          {!recentScans?.scans?.length && (
            <div className="px-4 py-8 text-center text-sm text-gray-500">
              No scans yet. Run <code className="text-indigo-400">codeguard scan</code> to get started.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
