import { NavLink, useNavigate } from 'react-router-dom';
import {
  ShieldCheck, LayoutDashboard, ScanLine, Database,
  Users, Settings, LogOut, Menu, X, ChevronRight
} from 'lucide-react';
import { useState } from 'react';
import { useAuthStore } from '../store/auth';
import clsx from 'clsx';

const NAV_ITEMS = [
  { to: '/',        icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',     icon: ScanLine,        label: 'Scans' },
  { to: '/ghin',      icon: Database,         label: 'GHIN Intel' },
  { to: '/teams',     icon: Users,            label: 'Teams' },
  { to: '/settings',  icon: Settings,         label: 'Settings' },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const { user, clearAuth } = useAuthStore();
  const navigate = useNavigate();

  function handleLogout() {
    clearAuth();
    navigate('/login');
  }

  return (
    <div className="flex h-screen bg-[#0f1117] overflow-hidden">
      {/* Sidebar */}
      <aside className={clsx(
        'flex flex-col bg-[#1a1d27] border-r border-[#2a2d3e] transition-all duration-200',
        sidebarOpen ? 'w-56' : 'w-14'
      )}>
        {/* Logo */}
        <div className="flex items-center gap-2 h-14 px-3 border-b border-[#2a2d3e]">
          <ShieldCheck className="w-7 h-7 text-indigo-400 shrink-0" />
          {sidebarOpen && (
            <span className="font-semibold text-white text-sm truncate">CodeGuard AI</span>
          )}
          <button
            onClick={() => setSidebarOpen(v => !v)}
            className="ml-auto text-gray-500 hover:text-gray-300"
          >
            {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 space-y-0.5 px-2">
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => clsx(
                'flex items-center gap-2.5 px-2 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-indigo-500/20 text-indigo-300'
                  : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {sidebarOpen && <span>{label}</span>}
              {sidebarOpen && <ChevronRight className="ml-auto w-3 h-3 opacity-30" />}
            </NavLink>
          ))}
        </nav>

        {/* User */}
        <div className="border-t border-[#2a2d3e] p-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-indigo-500/30 flex items-center justify-center text-xs font-bold text-indigo-300 shrink-0">
              {user?.name?.[0]?.toUpperCase() || user?.email?.[0]?.toUpperCase() || '?'}
            </div>
            {sidebarOpen && (
              <>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-gray-200 truncate">{user?.name || 'User'}</p>
                  <p className="text-[10px] text-gray-500 truncate">{user?.email}</p>
                </div>
                <button onClick={handleLogout} className="text-gray-500 hover:text-red-400">
                  <LogOut className="w-4 h-4" />
                </button>
              </>
            )}
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}
