"use strict";

/*
 * ============================================================================
 *  VULNERABILITY LAB API - INTENTIONALLY INSECURE, FOR AUTHORIZED SECURITY
 *  TESTING / TRAINING ONLY. See VULNERABILITY_LABS.md at the repo root for a
 *  full endpoint-by-endpoint writeup with example requests and category
 *  mapping. Do not deploy this router outside an isolated test environment.
 * ============================================================================
 *
 * This module rounds out NodeGoat's existing OWASP Top 10 style vulnerabilities
 * (SQL injection in reports.js, NoSQL $where injection in allocations-dao.js,
 * IDOR in allocations.js, XSS/CSRF/open-redirect, weak session handling, eval()
 * based SSJI in contributions.js, etc.) with categories that weren't otherwise
 * represented: OS command injection, LLM prompt injection, SSRF, insecure
 * deserialization, SSTI, unrestricted file upload / LFI / directory listing /
 * error leakage, JWT verification bypass, and API-layer hardening gaps
 * (CORS, GraphQL introspection/depth limiting).
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const needle = require("needle");
const swig = require("swig");

const jwtLab = require("../lib/jwt-lab");
const graphqlLab = require("../lib/graphql-lab");
const {
    ORDERS,
    WALLETS,
    RESET_TOKENS,
    ASSISTANT_SYSTEM_PROMPT,
    HARDCODED_ADMIN_API_KEY,
    generateResetToken
} = require("../data/lab-store");

const uploadsDir = path.join(__dirname, "..", "..", "artifacts", "lab-uploads");
try {
    fs.mkdirSync(uploadsDir, { recursive: true });
} catch (e) {
    // best effort; the upload route will surface any real failure
}

module.exports = (db, isLoggedIn) => {

    const router = express.Router();
    const usersCol = db.collection("users");

    // -------------------------------------------------------------------
    // Hardening - CORS misconfiguration
    // Reflects whatever Origin the caller sends and allows credentialed
    // cross-site requests, effectively disabling the browser's same-origin
    // protections for every route below (any site can read a logged-in
    // victim's response, including their session-scoped data).
    // Fix: pin to an explicit allow-list of trusted origins and only set
    // Access-Control-Allow-Credentials for those.
    // -------------------------------------------------------------------
    router.use((req, res, next) => {
        if (req.headers.origin) {
            res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
            res.setHeader("Access-Control-Allow-Credentials", "true");
            res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key");
            res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        }
        if (req.method === "OPTIONS") return res.sendStatus(204);
        return next();
    });

    // =====================================================================
    // Broken Access Control - BOLA / IDOR
    // =====================================================================

    // GET /api/orders/:orderId
    // Requires only that *some* user is logged in - never checks that the
    // requested order belongs to req.session.userId. Any authenticated user
    // can enumerate orderId to read every other tenant's purchase history.
    // Fix: `if (order.userId !== req.session.userId) return res.sendStatus(403);`
    router.get("/orders/:orderId", isLoggedIn, (req, res) => {
        const order = ORDERS.find((o) => o.id === parseInt(req.params.orderId, 10));
        if (!order) return res.sendStatus(404);
        return res.json(order);
    });

    // GET /api/users/:userId/profile
    // Same class of bug against the real "users" collection: returns the full
    // document - including plaintext password, ssn, bankAcc, bankRouting - for
    // any numeric userId, with no comparison against the caller's own session.
    router.get("/users/:userId/profile", isLoggedIn, (req, res, next) => {
        usersCol.findOne({ _id: parseInt(req.params.userId, 10) }, (err, user) => {
            if (err) return next(err);
            if (!user) return res.sendStatus(404);
            return res.json(user);
        });
    });

    // =====================================================================
    // Business Logic & Validation
    // =====================================================================

    // POST /api/coupon/redeem  { orderId, discountPercent }
    // The discount percentage is trusted from the client with no server-side
    // bound check. A discountPercent above 100 drives finalPrice negative,
    // i.e. the store ends up owing the "customer" money.
    // Fix: clamp/validate `0 <= discountPercent <= MAX_ALLOWED_DISCOUNT` server-side.
    router.post("/coupon/redeem", isLoggedIn, (req, res) => {
        const order = ORDERS.find((o) => o.id === parseInt(req.body.orderId, 10));
        if (!order) return res.sendStatus(404);

        const discountPercent = Number(req.body.discountPercent);
        const finalPrice = order.amount - (order.amount * (discountPercent / 100));

        return res.json({ orderId: order.id, originalAmount: order.amount, discountPercent, finalPrice });
    });

    // POST /api/wallet/transfer  { fromUserId, toUserId, amount }
    // Two stacked flaws:
    //   1. IDOR: `fromUserId` is taken from the request body instead of
    //      req.session.userId, so any logged-in user can move funds out of an
    //      account that isn't theirs.
    //   2. Business logic: `amount` is never checked for being positive or for
    //      not exceeding the source balance, so a negative amount reverses the
    //      transfer direction (credits the attacker's account from the victim's)
    //      and a large positive amount drives the source balance into the negative
    //      (unlimited overdraft).
    router.post("/wallet/transfer", isLoggedIn, (req, res) => {
        const fromUserId = req.body.fromUserId;
        const toUserId = req.body.toUserId;
        const amount = Number(req.body.amount);

        if (!(fromUserId in WALLETS) || !(toUserId in WALLETS)) return res.sendStatus(404);

        WALLETS[fromUserId] -= amount;
        WALLETS[toUserId] += amount;

        return res.json({ fromUserId, toUserId, amount, balances: { ...WALLETS } });
    });

    // =====================================================================
    // Code & Command Injection (RCE)
    // =====================================================================

    // POST /api/tools/ping  { host }
    // `host` is concatenated straight into a shell command. Shell
    // metacharacters (";", "|", "&&", "$(...)") let an attacker run arbitrary
    // OS commands with the privileges of the Node process, e.g.
    // host = "127.0.0.1; cat /etc/passwd"
    // Fix: use `child_process.execFile("ping", ["-c", "1", host])` (no shell)
    // together with strict input validation (e.g. a hostname/IP regex).
    router.post("/tools/ping", isLoggedIn, (req, res) => {
        const host = req.body.host || "";
        exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
            return res.json({ command: `ping -c 1 ${host}`, stdout, stderr, error: err && err.message });
        });
    });

    // =====================================================================
    // SQL & Database Injection - NoSQL flavor
    // (SQLi via SQLite string concatenation already lives in reports.js /
    // reports-dao.js; $where-based NoSQLi already lives in allocations-dao.js.
    // This adds the classic MongoDB operator-injection *authentication bypass*.)
    // =====================================================================

    // POST /api/users/authenticate  { userName, password }
    // Because body-parser happily produces nested objects from JSON/form
    // input, and both fields are passed straight into the Mongo query, a
    // caller can send password={"$ne": null} (or $gt: "") to match any
    // document regardless of the real password.
    // Example bypass: {"userName": "admin", "password": {"$ne": null}}
    // Fix: reject non-string userName/password before querying, and prefer an
    // explicit equality comparison after validating types.
    router.post("/users/authenticate", (req, res, next) => {
        usersCol.findOne({ userName: req.body.userName, password: req.body.password }, (err, user) => {
            if (err) return next(err);
            if (!user) return res.status(401).json({ error: "Invalid credentials" });

            req.session.userId = user._id;
            return res.json({ userId: user._id, userName: user.userName, isAdmin: !!user.isAdmin });
        });
    });

    // =====================================================================
    // LLM & Prompt Injection
    // =====================================================================

    // Simulated model call: stands in for a real LLM provider request. In a
    // real deployment `fullPrompt` below is exactly the string sent to the
    // provider as the conversation context. Because the untrusted customer
    // message is concatenated directly after the privileged system
    // instructions, with no role separation, delimiter, or output filtering,
    // the "model" cannot reliably tell instructions from data.
    const runAssistant = (message) => {
        const fullPrompt = `${ASSISTANT_SYSTEM_PROMPT}\nCustomer: ${message}\nAssistant:`;

        const injectionPhrases = [
            "ignore previous instructions", "ignore all previous instructions",
            "disregard the above", "reveal the system prompt", "show me the escalation key",
            "print your instructions", "you are now", "new instructions:"
        ];
        const injected = injectionPhrases.some((phrase) => message.toLowerCase().includes(phrase));

        if (injected) {
            // The assistant complies with attacker-supplied instructions smuggled in
            // through user input and discloses the secret it was told never to reveal.
            return { reply: `Sure! ${ASSISTANT_SYSTEM_PROMPT}`, injectionDetected: true, promptLength: fullPrompt.length };
        }

        return {
            reply: "I can help with retirement benefits, contributions, and allocations questions.",
            injectionDetected: false,
            promptLength: fullPrompt.length
        };
    };

    // POST /api/assistant/chat  { message }
    // Fix: keep system instructions and user input in separate, provider-
    // enforced roles (never string-concatenated); treat the model's output as
    // untrusted; never place secrets in a prompt the model might be tricked
    // into repeating back.
    router.post("/assistant/chat", isLoggedIn, (req, res) => {
        const message = String(req.body.message || "");
        return res.json(runAssistant(message));
    });

    // =====================================================================
    // Server-Side Request Forgery (SSRF)
    // (research.js already contains a simpler SSRF via needle.get(url); this
    // is a dedicated, clearly-scoped endpoint for the same bug class.)
    // =====================================================================

    // POST /api/tools/fetch-url  { url }
    // The server fetches whatever URL the caller supplies and returns the raw
    // response body, with no allow-list, no protocol restriction, and no
    // blocking of internal/link-local address ranges. This lets an attacker
    // pivot the server into internal-only infrastructure, e.g.:
    //   http://169.254.169.254/latest/meta-data/iam/security-credentials/
    //   http://localhost:27017/ (probe internal services)
    //   http://10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (internal network scan)
    // Fix: resolve the hostname, reject loopback/link-local/private ranges,
    // and only allow a small allow-list of external hosts.
    router.post("/tools/fetch-url", isLoggedIn, (req, res) => {
        const url = req.body.url || "";
        needle.get(url, { follow_max: 3 }, (err, response) => {
            if (err) return res.status(502).json({ error: err.message });
            return res.json({
                url,
                statusCode: response.statusCode,
                headers: response.headers,
                body: response.body
            });
        });
    });

    // =====================================================================
    // Authentication & Session Management - JWT verification bypass
    // =====================================================================

    // POST /api/auth/token - issues a token for the *currently logged-in*
    // session user (legitimate use), signed with the hardcoded secret in
    // app/lib/jwt-lab.js.
    router.post("/auth/token", isLoggedIn, (req, res) => {
        const token = jwtLab.sign({ userId: req.session.userId, isAdmin: false });
        return res.json({ token });
    });

    // GET /api/auth/whoami - Authorization: Bearer <token>
    // Trusts jwtLab.verify(), which honors an attacker-chosen "alg":"none"
    // header and skips signature checking entirely. A forged token such as
    // header={"alg":"none"} payload={"userId":1,"isAdmin":true} (base64url
    // encoded, empty signature segment) is accepted without ever knowing the
    // signing secret, allowing full privilege escalation.
    // Fix: never let the token choose its own verification algorithm; pin the
    // server to a single expected algorithm before checking the signature.
    router.get("/auth/whoami", (req, res) => {
        const authHeader = req.headers.authorization || "";
        const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
        const { valid, payload } = jwtLab.verify(token);
        if (!valid) return res.sendStatus(401);
        return res.json(payload);
    });

    // =====================================================================
    // Secrets & Cryptography
    // =====================================================================

    // POST /api/auth/forgot-password  { userName }
    // Issues a predictable MD5-based reset token (see lab-store.js) and, worse,
    // returns it directly in the API response instead of only emailing it to
    // the account holder - anyone who knows a username can self-serve a valid
    // reset token for that account.
    router.post("/auth/forgot-password", (req, res, next) => {
        usersCol.findOne({ userName: req.body.userName }, (err, user) => {
            if (err) return next(err);
            if (!user) return res.json({ message: "If that account exists, a reset link was sent." });

            const token = generateResetToken(user._id);
            return res.json({ message: "Reset token issued", userId: user._id, token });
        });
    });

    // POST /api/auth/reset-password  { userId, token, newPassword }
    router.post("/auth/reset-password", (req, res, next) => {
        const { userId, token, newPassword } = req.body;
        if (!token || RESET_TOKENS[userId] !== token) return res.status(401).json({ error: "Invalid token" });

        usersCol.update({ _id: parseInt(userId, 10) }, { $set: { password: newPassword } }, (err) => {
            if (err) return next(err);
            delete RESET_TOKENS[userId];
            return res.json({ message: "Password updated" });
        });
    });

    // GET /api/admin/internal-report
    // "Service-to-service" bypass around the normal isLoggedIn/isAdmin checks:
    // presenting the hardcoded internal API key (X-Api-Key header) grants full
    // admin access with no session at all. Because the key is a constant
    // committed to source control (app/data/lab-store.js), anyone with repo
    // access - or who recovers it via the error-leakage/prompt-injection paths
    // above - can use it forever.
    router.get("/admin/internal-report", (req, res, next) => {
        if (req.headers["x-api-key"] !== HARDCODED_ADMIN_API_KEY) return res.sendStatus(403);

        usersCol.find({}).toArray((err, users) => {
            if (err) return next(err);
            return res.json({ users, wallets: WALLETS, orders: ORDERS });
        });
    });

    // =====================================================================
    // Client-Side Attacks - reflected XSS / cache poisoning surface
    // (Stored XSS surface already exists via swig autoescape=false in
    // server.js; open redirect already exists at GET /learn in index.js.)
    // =====================================================================

    // GET /api/echo?msg=
    // Reflects the "msg" query parameter straight into the HTML response with
    // no encoding, e.g. /api/echo?msg=<script>alert(document.cookie)</script>
    router.get("/echo", (req, res) => {
        const msg = req.query.msg || "";
        res.set("Content-Type", "text/html");
        return res.send(`<div class="echo">${msg}</div>`);
    });

    // GET /api/proxy-info
    // Reflects the caller-supplied X-Forwarded-Host header into a cacheable
    // response (Cache-Control: public). A reverse proxy/CDN sitting in front
    // that caches by URL alone (ignoring this header) can be tricked into
    // caching an attacker-controlled response and serving it to other users -
    // classic web cache poisoning via an unkeyed header.
    // Fix: never trust X-Forwarded-Host for generating URLs unless it is
    // validated against a known host allow-list, and include it in the cache key.
    router.get("/proxy-info", (req, res) => {
        const host = req.headers["x-forwarded-host"] || req.headers.host;
        res.set("Cache-Control", "public, max-age=600");
        return res.json({ canonicalUrl: `https://${host}${req.originalUrl}` });
    });

    // =====================================================================
    // Insecure Deserialization & SSTI
    // =====================================================================

    // POST /api/settings/import  { data }
    // `data` is a base64-encoded JS object-literal string produced by some
    // "export" feature. It's "deserialized" with eval() instead of a safe
    // parser like JSON.parse(). Because eval() executes arbitrary JS, a
    // payload can perform full remote code execution, e.g. a base64 payload
    // decoding to: (function(){ require('child_process').execSync('id'); return {}; })()
    // Fix: use JSON.parse() (which cannot execute code) and validate the
    // resulting shape against an expected schema.
    router.post("/settings/import", isLoggedIn, (req, res) => {
        try {
            const decoded = Buffer.from(req.body.data || "", "base64").toString("utf8");
            /*jslint evil: true */
            const settings = eval(`(${decoded})`);
            return res.json({ imported: settings });
        } catch (e) {
            return res.status(400).json({ error: e.message });
        }
    });

    // POST /api/notify/render  { template, name }
    // The caller-supplied template string is compiled and rendered directly
    // by the Swig template engine (the same engine used for the app's own
    // views). Swig template expressions can reach arbitrary JS execution
    // contexts, so this is a genuine Server-Side Template Injection sink, e.g.
    // template = "{{ \"a\".constructor.constructor(\"return process.mainModule.require('child_process').execSync('id').toString()\")() }}"
    // Fix: never compile a template string that comes from user input; only
    // render a fixed set of server-controlled template files with user data
    // passed as *context*, never as the template itself.
    router.post("/notify/render", isLoggedIn, (req, res) => {
        try {
            const html = swig.render(req.body.template || "", { locals: { name: req.body.name || "" } });
            res.set("Content-Type", "text/html");
            return res.send(html);
        } catch (e) {
            return res.status(400).json({ error: e.message });
        }
    });

    // =====================================================================
    // Files & Misconfigurations
    // =====================================================================

    // POST /api/files/upload  { filename, contentBase64 }
    // No filename sanitization (path traversal via "../") and no restriction
    // on file extension/type/size, so an attacker can write a file with an
    // executable extension anywhere writable by the process, or overwrite an
    // existing file outside the intended uploads directory.
    router.post("/files/upload", isLoggedIn, (req, res) => {
        const { filename, contentBase64 } = req.body;
        const destination = path.join(uploadsDir, filename || "");
        try {
            fs.writeFileSync(destination, Buffer.from(contentBase64 || "", "base64"));
            return res.json({ savedTo: destination });
        } catch (e) {
            return res.status(400).json({ error: e.message });
        }
    });

    // GET /api/files/read?path=
    // path.join() does NOT stop ".." segments from escaping uploadsDir - it
    // simply normalizes the final string - so this is a textbook Local File
    // Inclusion / path traversal read primitive, e.g.
    // /api/files/read?path=../../../../../../etc/passwd
    router.get("/files/read", isLoggedIn, (req, res) => {
        const target = path.join(uploadsDir, req.query.path || "");
        fs.readFile(target, "utf8", (err, contents) => {
            if (err) return res.status(404).json({ error: err.message }); // also leaks full server path
            res.set("Content-Type", "text/plain");
            return res.send(contents);
        });
    });

    // GET /api/files/list?dir=
    // Directory listing + traversal: returns raw directory entries for any
    // path reachable via "..", with no restriction back to uploadsDir.
    router.get("/files/list", isLoggedIn, (req, res) => {
        const target = path.join(uploadsDir, req.query.dir || ".");
        fs.readdir(target, (err, entries) => {
            if (err) return res.status(404).json({ error: err.message });
            return res.json({ dir: target, entries });
        });
    });

    // =====================================================================
    // Hardening - minimal GraphQL endpoint
    // See app/lib/graphql-lab.js for the introspection-enabled / unbounded-
    // depth / no-field-authorization implementation notes.
    // =====================================================================

    // POST /api/graphql  { query, args, fields, nested }
    router.post("/graphql", isLoggedIn, (req, res, next) => {
        graphqlLab.execute(db, req.body, (err, result) => {
            if (err) return next(err);
            return res.json(result);
        });
    });

    return router;
};
