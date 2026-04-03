import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Key, Plus, Trash2, Copy, Check, ShieldCheck } from 'lucide-react';
import { authApi } from '../lib/api';
import { useAuthStore } from '../store/auth';

export default function Settings() {
  const { user } = useAuthStore();
  const qc = useQueryClient();
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const { data } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => authApi.apiKeys().then((r: any) => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (name: string) => authApi.createApiKey(name).then((r: any) => r.data),
    onSuccess: (data) => {
      setCreatedKey(data.key);
      setNewKeyName('');
      qc.invalidateQueries({ queryKey: ['api-keys'] });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => authApi.revokeApiKey(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });

  function copyKey() {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  const keys = data?.keys || [];

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Settings</h1>
        <p className="text-sm text-gray-500 mt-0.5">Manage your account and API keys</p>
      </div>

      {/* Profile */}
      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4 mb-6">
        <h2 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-indigo-400" /> Profile
        </h2>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-indigo-500/20 flex items-center justify-center text-indigo-300 font-bold">
            {user?.name?.[0]?.toUpperCase() || user?.email?.[0]?.toUpperCase()}
          </div>
          <div>
            <p className="text-sm text-gray-200 font-medium">{user?.name || 'User'}</p>
            <p className="text-xs text-gray-500">{user?.email}</p>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium mt-1 inline-block ${user?.role === 'ADMIN' ? 'bg-red-500/20 text-red-300' : 'bg-indigo-500/20 text-indigo-300'}`}>
              {user?.role}
            </span>
          </div>
        </div>
      </div>

      {/* New key created banner */}
      {createdKey && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 mb-4">
          <p className="text-xs text-emerald-400 mb-2 font-medium">
            ✅ API Key created — copy it now, it won't be shown again!
          </p>
          <div className="flex items-center gap-2 bg-[#0f1117] rounded-lg px-3 py-2">
            <code className="flex-1 text-xs text-emerald-300 font-mono break-all">{createdKey}</code>
            <button onClick={copyKey} className="text-gray-400 hover:text-emerald-400 shrink-0">
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <button onClick={() => setCreatedKey(null)} className="text-xs text-gray-500 mt-2 hover:text-gray-300">
            Dismiss
          </button>
        </div>
      )}

      {/* API Keys */}
      <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-[#2a2d3e] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
            <Key className="w-4 h-4 text-indigo-400" /> API Keys
          </h2>
          <div className="flex items-center gap-2">
            <input
              value={newKeyName}
              onChange={e => setNewKeyName(e.target.value)}
              placeholder="Key name (e.g. CI/CD)"
              className="bg-[#0f1117] border border-[#2a2d3e] rounded-lg px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-500 w-40"
            />
            <button
              onClick={() => newKeyName.trim() && createMutation.mutate(newKeyName.trim())}
              disabled={!newKeyName.trim() || createMutation.isPending}
              className="flex items-center gap-1 px-3 py-1.5 text-xs bg-indigo-600 hover:bg-indigo-700 disabled:opacity-40 text-white rounded-lg"
            >
              <Plus className="w-3 h-3" /> Create
            </button>
          </div>
        </div>

        {keys.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-500">
            No API keys yet. Create one to authenticate the CLI and GitHub Actions.
          </div>
        ) : (
          <div className="divide-y divide-[#2a2d3e]">
            {keys.map((key: any) => (
              <div key={key.id} className="px-4 py-3 flex items-center gap-3">
                <Key className="w-4 h-4 text-gray-500 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-200">{key.name}</p>
                  <p className="text-xs font-mono text-gray-500">{key.keyPrefix}•••••••••••••</p>
                </div>
                <div className="text-right text-xs text-gray-500">
                  {key.lastUsedAt ? `Used ${new Date(key.lastUsedAt).toLocaleDateString()}` : 'Never used'}
                </div>
                <button
                  onClick={() => revokeMutation.mutate(key.id)}
                  className="text-gray-600 hover:text-red-400 ml-2"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CLI setup hint */}
      <div className="mt-4 bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4">
        <p className="text-xs text-gray-500 font-medium mb-2">Using API keys with the CLI:</p>
        <pre className="bg-[#0f1117] rounded-lg p-3 text-xs font-mono text-gray-300 overflow-x-auto">
{`# Set via environment variable
export CODEGUARD_API_KEY=cg_your_key_here

# Or in .codeguard/config.json
{
  "apiUrl": "https://your-backend.railway.app",
  "apiKey": "cg_your_key_here"
}`}
        </pre>
      </div>
    </div>
  );
}
