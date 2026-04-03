# How to Build & Install the CodeGuard AI Extension

## Build for VS Code, Windsurf, and Cursor (all share the same `.vsix` format)

---

## Prerequisites

```bash
node --version   # Must be v18+
npm --version    # Must be v9+
```

Install the VS Code Extension packaging tool globally:

```bash
npm install -g @vscode/vsce
```

---

## Step 1: Install Dependencies

```bash
cd codeguard-ai
npm install
```

---

## Step 2: Compile TypeScript

```bash
npm run compile
```

Expected output: clean with 0 errors (22 pre-existing warnings are acceptable).

---

## Step 3: Package the Extension (.vsix file)

```bash
vsce package
```

This creates a file like: `codeguard-ai-7.0.0.vsix`

> **Note:** If you get a warning about missing publisher — that's OK for local install. Use `vsce package --no-yarn` if you're on npm.

---

## Step 4A: Install in VS Code

**Option 1 — Drag and drop:**
1. Open VS Code
2. Drag the `.vsix` file into the VS Code window

**Option 2 — Command Palette:**
1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
2. Type: `Extensions: Install from VSIX...`
3. Select the `.vsix` file

**Option 3 — Terminal:**
```bash
code --install-extension codeguard-ai-7.0.0.vsix
```

---

## Step 4B: Install in Windsurf

Windsurf is fully compatible with `.vsix` extension packages.

**Method 1 — Via UI:**
1. Open Windsurf
2. Click the **Extensions** icon in the sidebar (or press `Ctrl+Shift+X`)
3. Click the `...` menu (top-right of Extensions panel)
4. Select **"Install from VSIX..."**
5. Browse to and select `codeguard-ai-7.0.0.vsix`

**Method 2 — Via Terminal inside Windsurf:**
```bash
windsurf --install-extension codeguard-ai-7.0.0.vsix
```

---

## Step 4C: Install in Cursor

Cursor also uses the VS Code extension format.

1. Open Cursor
2. Press `Ctrl+Shift+P`
3. Type: `Extensions: Install from VSIX...`
4. Select `codeguard-ai-7.0.0.vsix`

Or via terminal:
```bash
cursor --install-extension codeguard-ai-7.0.0.vsix
```

---

## Step 5: Verify Installation

After installing:

1. Open any JavaScript or Python file in your editor
2. Add an import, e.g.:
   ```javascript
   import { faker } from 'faker-colors-js';  // ← known hallucination
   ```
3. You should see a **red squiggle** and a warning: *"Hallucinated package detected"*

Or open the Command Palette and run:
- `CodeGuard AI: Scan Current File`
- `CodeGuard AI: Open Dashboard`
- `CodeGuard AI: Scan MCP Servers`

---

## Step 6: Configure Backend URL (Optional)

To connect to your deployed backend for cloud sync:

1. Open VS Code Settings (`Ctrl+,`)
2. Search for `codeguard`
3. Set `CodeGuard AI: GHIN API URL` to your Railway/Render URL:
   ```
   https://codeguard-ai-backend-production.up.railway.app
   ```

Or add to `.vscode/settings.json`:
```json
{
  "codeguard.ghinApiUrl": "https://your-backend.railway.app"
}
```

---

## Development Mode (Hot Reload)

To develop the extension with live reloading:

```bash
# 1. Open the project in VS Code/Windsurf
code codeguard-ai/

# 2. Press F5 to launch Extension Development Host
# This opens a new editor window with the extension loaded live

# 3. Make changes to src/ files — press Ctrl+R in the dev host to reload
```

---

## Rebuild After Changes

```bash
npm run compile          # TypeScript → out/
vsce package             # Repackage → .vsix
code --install-extension codeguard-ai-*.vsix  # Reinstall
```

---

## Existing VSIX (Already Built)

A pre-built `codeguard-ai-5.2.0.vsix` is already in the repo root (323 KB).
You can install it directly without building:

```bash
code --install-extension codeguard-ai-5.2.0.vsix
```

> For the latest v7.0.0 features (MCP scanning, AI-SBOM), build fresh from source using steps above.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `vsce: command not found` | Run `npm install -g @vscode/vsce` |
| `Missing publisher` warning | Safe to ignore for local install. Add `--no-verify` if needed. |
| Extension not activating | Ensure you open a workspace folder (not just a file) |
| Squiggles not showing | Open a `.js`, `.ts`, `.py`, or `.json` file |
| `npm run compile` errors | Run `npm install` first, then compile |
| Windsurf can't find VSIX | Use absolute path: `windsurf --install-extension C:/full/path/to/codeguard-ai-7.0.0.vsix` |
