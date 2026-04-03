import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ScanLine, ShieldCheck, AlertTriangle, ChevronRight } from 'lucide-react';
import { scansApi } from '../lib/api';
import { format } from 'date-fns';

const SOURCE_BADGE: Record<string, string> = {
  CLI: 'bg-blue-500/20 text-blue-300',
  EXTENSION: 'bg-indigo-500/20 text-indigo-300',
  GITHUB_ACTION: 'bg-violet-500/20 text-violet-300',
  PRE_COMMIT: 'bg-emerald-500/20 text-emerald-300',
  API: 'bg-gray-500/20 text-gray-300',
};

export default function Scans() {
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list(page, 20).then(r => r.data),
  });

  const scans = data?.scans || [];
  const totalPages = data?.pagination?.pages || 1;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Scan History</h1>
          <p className="text-sm text-gray-500 mt-0.5">All security scans across your projects</p>
        </div>
        <div className="text-xs text-gray-500">{data?.pagination?.total ?? 0} total scans</div>
      </div>

      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-gray-500">Loading scans...</div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <ScanLine className="w-10 h-10 text-gray-600 mx-auto mb-3" />
            <p className="text-sm text-gray-400">No scans found</p>
            <p className="text-xs text-gray-600 mt-1">Run <code className="text-indigo-400">codeguard scan .</code> to upload your first scan</p>
          </div>
        ) : (
          <>
            <div className="divide-y divide-[#2a2d3e]">
              {scans.map((scan: any) => {
                const meta = scan.metadata || {};
                const summary = meta.summary || {};
                const totalFindings = summary.totalFindings ?? 0;
                const securityScore = meta.securityScore;
                return (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}`}
                  className="flex items-center gap-4 px-4 py-3 hover:bg-white/5 transition-colors"
                >
                  <div className={`p-2 rounded-lg ${totalFindings === 0 ? 'bg-emerald-500/20' : 'bg-amber-500/20'}`}>
                    {totalFindings === 0
                      ? <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      : <AlertTriangle className="w-4 h-4 text-amber-400" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-200 truncate">{meta.projectPath || 'Unknown project'}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${SOURCE_BADGE[scan.scanType] || 'bg-gray-500/20 text-gray-300'}`}>
                        {scan.scanType}
                      </span>
                      <span className="text-xs text-gray-500">{format(new Date(scan.startedAt), 'MMM d, yyyy HH:mm')}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`text-sm font-bold ${securityScore >= 80 ? 'text-emerald-400' : securityScore >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                      {securityScore ?? '—'}/100
                    </span>
                    <p className="text-xs text-gray-500">{totalFindings} findings</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-gray-600" />
                </Link>
                );
              })}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-2 px-4 py-3 border-t border-[#2a2d3e]">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 text-xs rounded bg-[#2a2d3e] text-gray-400 disabled:opacity-40"
                >
                  Prev
                </button>
                <span className="text-xs text-gray-500">{page} / {totalPages}</span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="px-3 py-1 text-xs rounded bg-[#2a2d3e] text-gray-400 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
