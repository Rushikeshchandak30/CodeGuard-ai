import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Github, Lock, Mail, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { supabase } from '../lib/supabase';
import { authApi } from '../lib/api';
import { useAuthStore } from '../store/auth';

type Tab = 'github' | 'admin';

export default function Login() {
  const navigate = useNavigate();
  const setToken = useAuthStore((s) => s.setToken);

  const [tab, setTab] = useState<Tab>('github');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleGithubLogin() {
    await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: { redirectTo: `${window.location.origin}/auth/callback` },
    });
  }

  async function handleAdminLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await authApi.adminLogin(email, password);
      const { token, user } = res.data;
      setToken(token, {
        id: user.id,
        email: user.email,
        name: user.name ?? 'Admin',
        avatarUrl: null,
        role: 'ADMIN',
        githubUsername: null,
      });
      navigate('/admin');
    } catch (err: any) {
      const msg = err?.response?.data?.error?.message || 'Invalid email or password';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#0f1117] flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center mb-4">
            <ShieldCheck className="w-8 h-8 text-indigo-400" />
          </div>
          <h1 className="text-2xl font-bold text-white">CodeGuard AI</h1>
          <p className="text-sm text-gray-500 mt-1">AI-Aware Security Platform</p>
        </div>

        {/* Card */}
        <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-2xl p-6">
          {/* Tabs */}
          <div className="flex rounded-xl bg-[#0f1117] p-1 mb-5 gap-1">
            <button
              onClick={() => { setTab('github'); setError(''); }}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium rounded-lg transition-colors ${
                tab === 'github'
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Github className="w-3.5 h-3.5" />
              Developer
            </button>
            <button
              onClick={() => { setTab('admin'); setError(''); }}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium rounded-lg transition-colors ${
                tab === 'admin'
                  ? 'bg-amber-600 text-white'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              Administrator
            </button>
          </div>

          {tab === 'github' && (
            <>
              <p className="text-xs text-gray-500 mb-5">
                Sign in with GitHub to access your security dashboard, scan history, and GHIN intelligence.
              </p>
              <button
                onClick={handleGithubLogin}
                className="w-full flex items-center justify-center gap-2.5 py-2.5 px-4 bg-white hover:bg-gray-100 text-gray-900 font-medium text-sm rounded-xl transition-colors"
              >
                <Github className="w-4 h-4" />
                Continue with GitHub
              </button>
            </>
          )}

          {tab === 'admin' && (
            <>
              <p className="text-xs text-gray-500 mb-5">
                Admin login uses credentials from your <code className="text-amber-400 bg-amber-400/10 px-1 rounded">.env</code> file. Full access to all system data and controls.
              </p>
              <form onSubmit={handleAdminLogin} className="space-y-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="admin@codeguard.ai"
                      className="w-full bg-[#0f1117] border border-[#2a2d3e] text-white text-sm rounded-xl pl-9 pr-4 py-2.5 placeholder-gray-600 focus:outline-none focus:border-amber-500/60 transition-colors"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full bg-[#0f1117] border border-[#2a2d3e] text-white text-sm rounded-xl pl-9 pr-10 py-2.5 placeholder-gray-600 focus:outline-none focus:border-amber-500/60 transition-colors"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                    >
                      {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="flex items-center gap-2 text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded-lg px-3 py-2">
                    <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 px-4 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium text-sm rounded-xl transition-colors"
                >
                  {loading ? 'Signing in…' : 'Sign in as Administrator'}
                </button>
              </form>
            </>
          )}

          <p className="text-center text-[11px] text-gray-600 mt-4">
            By signing in you agree to our{' '}
            <a href="#" className="text-indigo-400 hover:underline">Terms</a> and{' '}
            <a href="#" className="text-indigo-400 hover:underline">Privacy Policy</a>.
          </p>
        </div>

        {/* Feature list */}
        <div className="mt-6 grid grid-cols-2 gap-2">
          {[
            '🔍 520+ hallucinations DB',
            '🛡️ Real-time CVE detection',
            '🤖 MCP server scanning',
            '📊 Scan history & trends',
          ].map(f => (
            <div key={f} className="text-xs text-gray-500 bg-[#1a1d27] border border-[#2a2d3e] rounded-lg px-3 py-2">
              {f}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
