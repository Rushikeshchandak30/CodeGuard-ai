import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Database, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { ghinApi } from '../lib/api';

const STATUS_STYLE: Record<string, { label: string; cls: string; Icon: any }> = {
  CONFIRMED:     { label: 'Confirmed',     cls: 'text-red-400 bg-red-500/10 border-red-500/30',       Icon: XCircle },
  SUSPECTED:     { label: 'Suspected',     cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30', Icon: AlertTriangle },
  FALSE_POSITIVE:{ label: 'False Positive',cls: 'text-blue-400 bg-blue-500/10 border-blue-500/30',   Icon: CheckCircle },
  MALICIOUS:     { label: 'Malicious',     cls: 'text-red-600 bg-red-900/20 border-red-700/30',       Icon: AlertTriangle },
};

const ECOSYSTEMS = ['', 'NPM', 'PYPI', 'CARGO', 'GEM', 'GO'];
const STATUSES   = ['', 'CONFIRMED', 'SUSPECTED', 'FALSE_POSITIVE', 'MALICIOUS'];

export default function GhinPackages() {
  const [page, setPage] = useState(1);
  const [ecosystem, setEcosystem] = useState('');
  const [status, setStatus] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['ghin-packages', page, ecosystem, status],
    queryFn: () => ghinApi.packages(page, status || undefined, ecosystem || undefined).then(r => r.data),
  });

  const { data: statsData } = useQuery({
    queryKey: ['ghin-stats'],
    queryFn: () => ghinApi.stats().then(r => r.data),
  });

  const packages = data?.packages || [];
  const totalPages = data?.pagination?.pages || 1;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">GHIN Intelligence</h1>
        <p className="text-sm text-gray-500 mt-0.5">Global Hallucination Intelligence Network — crowdsourced package intelligence</p>
      </div>

      {/* Stats banner */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Total Packages',         value: statsData?.totalPackages ?? 0,         color: 'text-white' },
          { label: 'Confirmed Hallucinations',value: statsData?.confirmedHallucinations ?? 0, color: 'text-red-400' },
          { label: 'Total Reports',           value: statsData?.totalReports ?? 0,           color: 'text-indigo-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4">
            <div className={`text-2xl font-bold ${color}`}>{value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap">
        <select
          value={ecosystem}
          onChange={e => { setEcosystem(e.target.value); setPage(1); }}
          className="bg-[#1a1d27] border border-[#2a2d3e] text-sm text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500"
        >
          {ECOSYSTEMS.map(e => <option key={e} value={e}>{e || 'All Ecosystems'}</option>)}
        </select>
        <select
          value={status}
          onChange={e => { setStatus(e.target.value); setPage(1); }}
          className="bg-[#1a1d27] border border-[#2a2d3e] text-sm text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500"
        >
          {STATUSES.map(s => <option key={s} value={s}>{s || 'All Statuses'}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-gray-500">Loading...</div>
        ) : packages.length === 0 ? (
          <div className="p-12 text-center">
            <Database className="w-10 h-10 text-gray-600 mx-auto mb-3" />
            <p className="text-sm text-gray-400">No packages found</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-[#2a2d3e]">
                <th className="text-left px-4 py-2.5 font-medium">Package</th>
                <th className="text-left px-4 py-2.5 font-medium">Ecosystem</th>
                <th className="text-left px-4 py-2.5 font-medium">Status</th>
                <th className="text-right px-4 py-2.5 font-medium">Reports</th>
                <th className="text-right px-4 py-2.5 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2a2d3e]">
              {packages.map((pkg: any) => {
                const style = STATUS_STYLE[pkg.status] || STATUS_STYLE.SUSPECTED;
                const Icon = style.Icon;
                return (
                  <tr key={pkg.id} className="hover:bg-white/5">
                    <td className="px-4 py-2.5 font-mono text-gray-200">{pkg.packageName}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300">{pkg.ecosystem}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`flex items-center gap-1 text-xs w-fit px-1.5 py-0.5 rounded border ${style.cls}`}>
                        <Icon className="w-3 h-3" />{style.label}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right text-gray-400">{pkg.reportCount}</td>
                    <td className="px-4 py-2.5 text-right text-gray-500 text-xs">
                      {pkg.lastSeenAt ? new Date(pkg.lastSeenAt).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2 px-4 py-3 border-t border-[#2a2d3e]">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="px-3 py-1 text-xs rounded bg-[#2a2d3e] text-gray-400 disabled:opacity-40">Prev</button>
            <span className="text-xs text-gray-500">{page} / {totalPages}</span>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
              className="px-3 py-1 text-xs rounded bg-[#2a2d3e] text-gray-400 disabled:opacity-40">Next</button>
          </div>
        )}
      </div>
    </div>
  );
}
