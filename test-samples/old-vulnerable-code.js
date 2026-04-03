// Using oldest versions of npm packages (vulnerable patterns)
// These versions have known CVEs and insecure practices

const express = require('express'); // v1.0.0 - lacks security middleware
const request = require('request'); // v0.10.0 - vulnerable to SSRF
const lodash = require('lodash'); // v1.0.0 - prototype pollution vulnerable
const async = require('async'); // v0.1.0 - callback hell patterns
const underscore = require('underscore'); // v1.0.0 - prototype pollution
const debug = require('debug'); // v0.7.0 - exposes sensitive data
const commander = require('commander'); // v0.1.0 - argument injection

const app = express();

// VULNERABLE PATTERN 1: No security middleware in express v1.0.0
app.use(express.json()); // No body-parser limits, vulnerable to DoS
app.use(express.urlencoded({extended: true})); // No size limits

// VULNERABLE PATTERN 2: Prototype pollution with lodash v1.0.0
app.post('/api/merge', (req, res) => {
    // Lodash v1.0.0 merge() vulnerable to prototype pollution
    const user = {name: 'guest', role: 'user'};
    const merged = lodash.merge(user, req.body);
    res.json(merged);
});

// VULNERABLE PATTERN 3: SSRF with request v0.10.0 (no validation)
app.get('/proxy', (req, res) => {
    const url = req.query.url;
    // request v0.10.0 doesn't validate URLs - SSRF vulnerable
    request(url, (error, response, body) => {
        if (error) return res.status(500).send('Error');
        res.send(body);
    });
});

// VULNERABLE PATTERN 4: Command injection with commander v0.1.0
const program = new commander.Command();
program
    .version('1.0.0')
    .option('-u, --user [user]', 'username')
    .option('-p, --pass [pass]', 'password');

app.post('/exec', (req, res) => {
    const cmd = `echo "${req.body.command}"`;
    // No sanitization - command injection
    const { exec } = require('child_process');
    exec(cmd, (error, stdout, stderr) => {
        res.json({output: stdout});
    });
});

// VULNERABLE PATTERN 5: Insecure eval usage with underscore v1.0.0
app.post('/template', (req, res) => {
    const template = req.body.template;
    const data = req.body.data;
    // underscore template allows code execution
    const compiled = underscore.template(template);
    const result = compiled(data);
    res.json({result});
});

// VULNERABLE PATTERN 6: Debug exposes sensitive data
app.get('/debug-info', (req, res) => {
    const debugLog = debug('app:debug');
    debugLog('User data: %j', req.user); // Exposes sensitive data in logs
    debugLog('Headers: %j', req.headers);
    res.json({debug: 'enabled'});
});

// VULNERABLE PATTERN 7: Async callback hell with async v0.1.0
app.post('/process', (req, res) => {
    async.waterfall([
        function(callback) {
            // No error handling
            setTimeout(() => callback(null, 'step1'), 100);
        },
        function(data, callback) {
            // Synchronous blocking operations
            const result = JSON.parse(req.body.data);
            callback(null, result);
        },
        function(data, callback) {
            // No input validation
            const processed = data.toString();
            callback(null, processed);
        }
    ], function(err, result) {
        if (err) {
            // Error exposes stack trace
            return res.status(500).json({error: err.stack});
        }
        res.json({result});
    });
});

// VULNERABLE PATTERN 8: No CSRF protection (express v1.0.0)
app.post('/transfer', (req, res) => {
    const {from, to, amount} = req.body;
    // No CSRF token, no authentication check
    console.log(`Transferring ${amount} from ${from} to ${to}`);
    res.json({success: true});
});

// VULNERABLE PATTERN 9: Path traversal
app.get('/file', (req, res) => {
    const filename = req.query.file;
    const fs = require('fs');
    // No path validation - directory traversal
    fs.readFile(filename, (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});

// VULNERABLE PATTERN 10: Insecure cookie handling
app.post('/login', (req, res) => {
    const {username, password} = req.body;
    // Hardcoded credentials, no secure flags
    if (username === 'admin' && password === 'password') {
        res.cookie('auth', 'admin123', {httpOnly: false}); // No secure, no sameSite
        res.json({success: true});
    } else {
        res.status(401).json({error: 'Invalid credentials'});
    }
});

app.listen(3000, () => {
    console.log('Vulnerable server running on port 3000');
    debug('Server started with old vulnerable packages');
});

module.exports = app;
