import { useQuery } from '@tanstack/react-query';
import { Users, Shield, Crown } from 'lucide-react';
import { teamsApi } from '../lib/api';

export default function Teams() {
  const { data, isLoading } = useQuery({
    queryKey: ['teams'],
    queryFn: () => teamsApi.list().then((r: any) => r.data),
  });

  const teams = data?.teams || [];

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Teams</h1>
        <p className="text-sm text-gray-500 mt-0.5">Manage your teams and members</p>
      </div>
      {isLoading ? (
        <div className="text-sm text-gray-500">Loading...</div>
      ) : teams.length === 0 ? (
        <div className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-12 text-center">
          <Users className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-sm text-gray-400">No teams yet</p>
          <p className="text-xs text-gray-600 mt-1">Create a team to collaborate with your security squad</p>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {teams.map((team: any) => (
            <div key={team.id} className="bg-[#1a1d27] border border-[#2a2d3e] rounded-xl p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-9 h-9 rounded-lg bg-indigo-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-indigo-400" />
                </div>
                <div>
                  <p className="font-semibold text-white text-sm">{team.name}</p>
                  <p className="text-xs text-gray-500">{team.slug}</p>
                </div>
              </div>
              <div className="flex items-center justify-between text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <Users className="w-3 h-3" /> {team._count?.members ?? 0} members
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${team.plan === 'FREE' ? 'bg-gray-500/20 text-gray-400' : 'bg-indigo-500/20 text-indigo-300'}`}>
                  {team.plan}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
