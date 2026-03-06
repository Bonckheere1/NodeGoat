const SessionHandler = require("./session");
const ProfileHandler = require("./profile");
const BenefitsHandler = require("./benefits");
const ContributionsHandler = require("./contributions");
const AllocationsHandler = require("./allocations");
const MemosHandler = require("./memos");
const ResearchHandler = require("./research");
const VulnerableHandler = require("./vulnerable");
const tutorialRouter = require("./tutorial");
const ErrorHandler = require("./error").errorHandler;

const index = (app, db) => {

    "use strict";

    const sessionHandler = new SessionHandler(db);
    const profileHandler = new ProfileHandler(db);
    const benefitsHandler = new BenefitsHandler(db);
    const contributionsHandler = new ContributionsHandler(db);
    const allocationsHandler = new AllocationsHandler(db);
    const memosHandler = new MemosHandler(db);
    const researchHandler = new ResearchHandler(db);
    const vulnerableHandler = new VulnerableHandler(db);

    // Middleware to check if a user is logged in
    const isLoggedIn = sessionHandler.isLoggedInMiddleware;

    //Middleware to check if user has admin rights
    const isAdmin = sessionHandler.isAdminUserMiddleware;

    // The main page of the app
    app.get("/", sessionHandler.displayWelcomePage);

    // Login form
    app.get("/login", sessionHandler.displayLoginPage);
    app.post("/login", sessionHandler.handleLoginRequest);

    // Signup form
    app.get("/signup", sessionHandler.displaySignupPage);
    app.post("/signup", sessionHandler.handleSignup);

    // Logout page
    app.get("/logout", sessionHandler.displayLogoutPage);

    // The main page of the app
    app.get("/dashboard", isLoggedIn, sessionHandler.displayWelcomePage);

    // Profile page
    app.get("/profile", isLoggedIn, profileHandler.displayProfile);
    app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);

    // Contributions Page
    app.get("/contributions", isLoggedIn, contributionsHandler.displayContributions);
    app.post("/contributions", isLoggedIn, contributionsHandler.handleContributionsUpdate);

    // Benefits Page
    app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
    app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
    /* Fix for A7 - checks user role to implement  Function Level Access Control
     app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
     app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
     */

    // Allocations Page
    app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);

    // Memos Page
    app.get("/memos", isLoggedIn, memosHandler.displayMemos);
    app.post("/memos", isLoggedIn, memosHandler.addMemos);

    // Handle redirect for learning resources link
    app.get("/learn", isLoggedIn, (req, res) => {
        // Insecure way to handle redirects by taking redirect url from query string
        return res.redirect(req.query.url);
    });

    // Research Page
    app.get("/research", isLoggedIn, researchHandler.displayResearch);

    // Mount tutorial router
    app.use("/tutorial", tutorialRouter);

    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABLE LAB ROUTES  (educational / security-testing purposes only)
    // ─────────────────────────────────────────────────────────────────────────

    // Main demo page
    app.get("/vulnerable", isLoggedIn, vulnerableHandler.displayVulnerablePage);

    // 1. Broken Access Control — BOLA / IDOR
    app.get("/vulnerable/user/:userId",     isLoggedIn, vulnerableHandler.getUserById);
    app.get("/vulnerable/document/:docId",  isLoggedIn, vulnerableHandler.getDocument);
    app.put("/vulnerable/account/:userId",  isLoggedIn, vulnerableHandler.updateAccount);
    app.get("/vulnerable/admin-panel",      isLoggedIn, vulnerableHandler.adminPanel); // Missing isAdmin

    // 2. Business Logic & Validation
    app.post("/vulnerable/checkout", isLoggedIn, vulnerableHandler.checkout);
    app.post("/vulnerable/coupon",   isLoggedIn, vulnerableHandler.applyCoupon);
    app.post("/vulnerable/transfer", isLoggedIn, vulnerableHandler.transfer);

    // 3. Code & Command Injection
    app.get("/vulnerable/ping",      isLoggedIn, vulnerableHandler.ping);
    app.get("/vulnerable/eval",      isLoggedIn, vulnerableHandler.evalExpression);
    app.post("/vulnerable/eval",     isLoggedIn, vulnerableHandler.evalExpression);
    app.get("/vulnerable/file-info", isLoggedIn, vulnerableHandler.fileInfo);

    // 4. NoSQL / Database Injection
    app.post("/vulnerable/login-nosql",  vulnerableHandler.nosqlLogin);       // No auth required
    app.get("/vulnerable/db-search",     isLoggedIn, vulnerableHandler.searchByField); // $where injection
    app.get("/vulnerable/ldap",          isLoggedIn, vulnerableHandler.ldapSearch);

    // 5. LLM & Prompt Injection
    app.post("/vulnerable/ai/chat",      isLoggedIn, vulnerableHandler.aiChat);
    app.post("/vulnerable/ai/review",    isLoggedIn, vulnerableHandler.aiReview);
    app.post("/vulnerable/ai/summarize", isLoggedIn, vulnerableHandler.aiSummarize);

    // 6. SSRF
    app.get("/vulnerable/fetch",        isLoggedIn, vulnerableHandler.fetchUrl);
    app.post("/vulnerable/webhook",     isLoggedIn, vulnerableHandler.sendWebhook);

    // 7. Authentication & Session Management
    app.get("/vulnerable/token/generate", isLoggedIn, vulnerableHandler.generateToken);
    app.get("/vulnerable/token/verify",   vulnerableHandler.verifyToken);  // No auth — intentional
    app.get("/vulnerable/reset-password", vulnerableHandler.resetPassword);
    app.post("/vulnerable/brute-login",   vulnerableHandler.bruteLogin);

    // 8. Client-Side Attacks (XSS, Open Redirect)
    app.get("/vulnerable/search",       isLoggedIn, vulnerableHandler.searchPage);
    app.post("/vulnerable/comment",     isLoggedIn, vulnerableHandler.addComment);
    app.get("/vulnerable/comments",     isLoggedIn, vulnerableHandler.listComments);
    app.get("/vulnerable/redirect",     isLoggedIn, vulnerableHandler.openRedirect);
    app.get("/vulnerable/dom-xss",      isLoggedIn, vulnerableHandler.domXssPage);

    // 9. Insecure Deserialization & SSTI
    app.post("/vulnerable/preferences", isLoggedIn, vulnerableHandler.loadPreferences);
    app.get("/vulnerable/template",     isLoggedIn, vulnerableHandler.renderTemplate);
    app.post("/vulnerable/template",    isLoggedIn, vulnerableHandler.renderTemplate);

    // 10. Files & Misconfigurations
    app.get("/vulnerable/files/download", isLoggedIn, vulnerableHandler.downloadFile);
    app.post("/vulnerable/files/upload",  isLoggedIn, vulnerableHandler.uploadFile);
    app.get("/vulnerable/error",          isLoggedIn, vulnerableHandler.triggerError);

    // 11. Secrets & Cryptography
    app.get("/vulnerable/crypto/hash",  isLoggedIn, vulnerableHandler.hashData);
    app.get("/vulnerable/crypto/ecb",   isLoggedIn, vulnerableHandler.ecbEncrypt);
    app.post("/vulnerable/payment",     isLoggedIn, vulnerableHandler.processPayment);

    // 12. Hardening
    app.get("/vulnerable/cors-data",    isLoggedIn, vulnerableHandler.corsData);
    app.post("/vulnerable/graphql",     vulnerableHandler.graphql);  // No auth — intentional
    app.get("/vulnerable/no-headers",   isLoggedIn, vulnerableHandler.noSecurityHeaders);

    // Error handling middleware
    app.use(ErrorHandler);
};

module.exports = index;
