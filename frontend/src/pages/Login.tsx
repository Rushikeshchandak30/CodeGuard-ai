import { ShieldCheck, Github } from 'lucide-react';
import { supabase } from '../lib/supabase';

export default function Login() {
  async function handleGithubLogin() {
    await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`,
      },
    });
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
          <h2 className="text-base font-semibold text-white mb-1">Sign in</h2>
          <p className="text-xs text-gray-500 mb-6">
            Sign in to access your security dashboard, scan history, and GHIN intelligence.
          </p>

          <button
            onClick={handleGithubLogin}
            className="w-full flex items-center justify-center gap-2.5 py-2.5 px-4 bg-white hover:bg-gray-100 text-gray-900 font-medium text-sm rounded-xl transition-colors"
          >
            <Github className="w-4 h-4" />
            Continue with GitHub
          </button>

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
