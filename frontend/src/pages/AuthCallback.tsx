import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/auth';
import { supabase } from '../lib/supabase';
import { Loader2 } from 'lucide-react';

export default function AuthCallback() {
  const navigate = useNavigate();
  const setToken = useAuthStore((state) => state.setToken);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function handleCallback() {
      try {
        // Supabase puts tokens in the URL hash: #access_token=...&refresh_token=...
        // getSession() reads these automatically from the URL hash
        const { data, error: sessionError } = await supabase.auth.getSession();

        if (sessionError || !data.session) {
          // Try to get user from hash manually
          const hash = window.location.hash.substring(1);
          const hashParams = new URLSearchParams(hash);
          const accessToken = hashParams.get('access_token');

          if (!accessToken) {
            setError('Authentication failed. No session found.');
            setTimeout(() => navigate('/login'), 2000);
            return;
          }

          // Use the access token directly to call our backend
          await exchangeWithBackend(accessToken);
          return;
        }

        await exchangeWithBackend(data.session.access_token);
      } catch (err) {
        setError('Authentication failed. Please try again.');
        setTimeout(() => navigate('/login'), 2000);
      }
    }

    async function exchangeWithBackend(supabaseToken: string) {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:3000';
      const res = await fetch(`${apiUrl}/api/auth/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ supabaseToken }),
      });

      if (!res.ok) {
        setError('Backend session creation failed.');
        setTimeout(() => navigate('/login'), 2000);
        return;
      }

      const { token, user } = await res.json();
      setToken(token, user);
      navigate('/');
    }

    handleCallback();
  }, [navigate, setToken]);

  if (error) {
    return (
      <div className="min-h-screen bg-[#0f1117] flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-400 mb-2">{error}</p>
          <p className="text-gray-500 text-sm">Redirecting to login...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f1117] flex items-center justify-center">
      <div className="text-center">
        <Loader2 className="w-8 h-8 text-indigo-400 animate-spin mx-auto mb-4" />
        <p className="text-gray-400">Completing authentication...</p>
      </div>
    </div>
  );
}
