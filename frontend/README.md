# CodeGuard AI — Web Dashboard

React + Vite + TailwindCSS dashboard for the CodeGuard AI platform.

## Setup

```bash
cd frontend
npm install
cp ../.env.example .env.local   # then set VITE_API_URL
npm run dev                      # http://localhost:5173
```

## Environment Variables

Create `frontend/.env.local`:
```env
VITE_API_URL=http://localhost:3000
```

For production:
```env
VITE_API_URL=https://your-backend.railway.app
```

## Build for Production

```bash
npm run build    # outputs to frontend/dist/
npm run preview  # preview production build locally
```

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/login` | Login | GitHub OAuth sign-in |
| `/dashboard` | Dashboard | Security score, charts, recent scans |
| `/scans` | Scans | Paginated scan history |
| `/scans/:id` | ScanDetail | Full findings for one scan |
| `/ghin` | GhinPackages | Browse GHIN intelligence network |
| `/teams` | Teams | Team management |
| `/settings` | Settings | Profile + API key management |

## Tech Stack

- **React 18** — UI framework
- **Vite 5** — Build tool
- **TailwindCSS 3** — Styling
- **React Router v6** — Routing
- **TanStack Query v5** — Data fetching + caching
- **Zustand** — Auth state (persisted in localStorage)
- **Recharts** — Charts (area chart for trends)
- **Lucide React** — Icons
- **Axios** — HTTP client (with auth interceptors)
- **date-fns** — Date formatting
