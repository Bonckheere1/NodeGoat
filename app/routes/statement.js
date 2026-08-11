const fs = require("fs");
const path = require("path");
const StatementDAO = require("../data/statement-dao").StatementDAO;
const { exportStatementToFile, EXPORT_DIR } = require("../utils/statement-export");
const {
    environmentalScripts
} = require("../../config/config");

/* The StatementHandler must be constructed with a connected db */
function StatementHandler(db) {
    "use strict";

    const statementDAO = new StatementDAO(db);

    /*
     * A4 - Missing Function Level Access Control / Insecure Direct Object
     * Reference. The account whose statements are displayed is taken from the
     * URL (:userId) instead of the authenticated session, and nothing checks
     * that the logged-in user owns that account. Any logged-in user can view
     * another user's statement history and notes just by changing the userId
     * segment of the URL, e.g. /statement/1, /statement/2, /statement/3, ...
     *
     * Fix:
     *   const { userId } = req.session;
     *   if (parseInt(req.params.userId, 10) !== parseInt(userId, 10)) {
     *       return res.redirect("/dashboard");
     *   }
     */
    this.displayStatement = (req, res, next) => {
        const {
            userId
        } = req.params;
        const {
            search
        } = req.query;

        statementDAO.getAllForUser(userId, { search }, (err, statements) => {
            if (err) return next(err);

            return res.render("statement", {
                userId,
                statements,
                searchTerm: search || "",
                environmentalScripts
            });
        });
    };

    this.handleExportRequest = (req, res, next) => {
        const {
            userId
        } = req.params;
        const {
            fileName,
            notes
        } = req.body;

        statementDAO.getAllForUser(userId, {}, (err, previousStatements) => {
            if (err) return next(err);

            statementDAO.insert(userId, fileName, notes, (err) => {
                if (err) return next(err);

                // Sink for the OS command injection - see app/utils/statement-export.js
                exportStatementToFile(fileName, notes, previousStatements, (err) => {
                    if (err) return next(err);
                    return res.redirect(`/statement/${userId}`);
                });
            });
        });
    };

    /*
     * A5 - Path Traversal / Arbitrary File Read. fileName comes straight from
     * the URL and is joined onto EXPORT_DIR with no validation, so "../"
     * sequences escape the export directory entirely.
     *
     * Example: GET /statement/1/download/..%2f..%2f..%2f..%2fetc%2fpasswd
     *
     * Fix: strip path separators from fileName, or resolve the final path and
     * verify it still starts with EXPORT_DIR before reading it.
     */
    this.downloadStatement = (req, res, next) => {
        const {
            fileName
        } = req.params;
        const filePath = path.join(EXPORT_DIR, fileName);

        fs.readFile(filePath, "utf8", (err, data) => {
            if (err) return next(err);
            res.set("Content-Type", "text/plain");
            return res.send(data);
        });
    };

    /*
     * A8 - CSRF, combined with the same missing ownership check as above.
     * Deletion is a state-changing action exposed via a plain GET request with
     * no CSRF token, so a forged request from another site
     * (e.g. <img src="https://target/statement/3/delete/august-2026">) executes
     * using the victim's authenticated session the moment they view it.
     */
    this.deleteStatement = (req, res, next) => {
        const {
            userId,
            fileName
        } = req.params;

        statementDAO.remove(userId, fileName, (err) => {
            if (err) return next(err);

            const filePath = path.join(EXPORT_DIR, fileName);
            fs.unlink(filePath, () => {
                return res.redirect(`/statement/${userId}`);
            });
        });
    };

}

module.exports = StatementHandler;
