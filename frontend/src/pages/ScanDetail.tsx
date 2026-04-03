import { useQuery } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ShieldCheck, AlertTriangle, Eye, Key, Code2, Server } from 'lucide-react';
import { scansApi } from '../lib/api';
import { format } from 'date-fns';

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM:   'text-amber-400 bg-amber-500/10 border-amber-500/30',
  LOW:      'text-blue-400 bg-blue-500/10 border-blue-500/30',
};

const TYPE_ICON: Record<string, any> = {
  hallucination: Eye,
  secret: Key,
  sast: Code2,
  mcp: Server,
  vulnerability: AlertTriangle,
};

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, error } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scansApi.get(id!).then(r => r.data),
    enabled: !!id,
  });

  if (isLoading) return <div className="p-8 text-center text-sm text-gray-500">Loading scan...</div>;
  if (error || !data) return (
    <div className="p-8 text-center">
      <p className="text-red-400 text-sm">Scan not found.</p>
      <Link to="/scans" className="text-xs text-indigo-400 mt-2 block">← Back to scans</Link>
    </div>
  );

  const scan = data.scan;
  const meta = scan.metadata || {};
  const summary = meta.summary || {};
  const findings: any[] = scan.findings || [];

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <Link to="/scans" className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-4">
        <ArrowLeft className="w-3 h-3" /> Back to scans
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-lg font-bold text-white font-mono">{meta.projectPath || 'Scan'}</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            {format(new Date(scan.startedAt), 'MMM d, yyyy HH:mm')} · {scan.scanType}
            {meta.branch && <> · <span className="text-indigo-400">{meta.branch}</span></>}
          </p>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-bold ${(meta.securityScore ?? 0) >= 80 ? 'text-emerald-400' : (meta.securityScore ?? 0) >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
            {meta.securityScore ?? '—'}/100
          </div>
          <p className="text-xs text-gray-500">Security Score</p>
        </div>
      </div>

      {/* Summary badges */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 mb-6">
        {[
          { label: 'Critical', value: summary.critical ?? 0, color: 'text-red-400' },
          { label: 'High', value: summary.high ?? 0, color: 'text-orange-400' },
          { label: 'Medium', value: summary.medium ?? 0, color: 'text-amber-400' },
          { label: 'Hallucinations', value: summary.hallucinatedPackages ?? 0, color: 'text-violet-400' },
          { label: 'Secrets', value: summary.secretsFound ?? 0, color: 'text-pink-400' },
          { label: 'CVEs', value: summary.vulnerabilities ?? 0, color: 'text-red-300' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#1a1d27] border border-[#2a2d3e] rounded-lg p-3 text-center">
            <div className={`text-lg font-bold ${color}`}>{value}</div>
            <div className="text-[10px] text-gray-500">{label}</div>
          </div>
        ))}
      </div>

      {/* Findings */}
      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-[#2a2d3e]">
          <h2 className="text-sm font-semibold text-gray-300">Findings ({findings.length})</h2>
        </div>
        {findings.length === 0 ? (
          <div className="p-8 text-center">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            <p className="text-sm text-emerald-400">No findings — clean scan!</p>
          </div>
        ) : (
          <div className="divide-y divide-[#2a2d3e]">
            {findings.map((f: any, i: number) => {
              const Icon = TYPE_ICON[f.type] || AlertTriangle;
              return (
                <div key={i} className="px-4 py-3 flex items-start gap-3">
                  <div className="mt-0.5">
                    <Icon className="w-4 h-4 text-gray-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase ${SEVERITY_COLOR[f.severity] || 'text-gray-400 bg-gray-500/10 border-gray-500/30'}`}>
                        {f.severity}
                      </span>
                      <span className="text-xs text-gray-500 uppercase tracking-wide">{f.type}</span>
                      {f.packageName && <span className="text-xs text-indigo-300 font-mono">{f.packageName}</span>}
                    </div>
                    <p className="text-sm text-gray-200 mt-1">{f.message || f.description}</p>
                    {f.file && <p className="text-xs text-gray-500 font-mono mt-0.5">{f.file}{f.line ? `:${f.line}` : ''}</p>}
                    {f.fix && <p className="text-xs text-emerald-400 mt-1">💡 {f.fix}</p>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
