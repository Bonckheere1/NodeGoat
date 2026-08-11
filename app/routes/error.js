// Error handling middleware

const errorHandler = (err, req, res,next) => {

    "use strict";

    console.error(err.message);
    console.error(err.stack);
    res.status(500);

    // Files & Misconfigurations - Error Leakage
    // The full stack trace (file paths, line numbers, module names, and
    // sometimes query/parameter values baked into the error message) is sent
    // to every client, in every environment - there's no NODE_ENV check
    // gating verbose output to development only. This hands an attacker a
    // roadmap of the server's internals and, for injection bugs (SQL/NoSQL/
    // command), often the raw underlying query or command.
    // Fix: only render `err.stack` when process.env.NODE_ENV !== "production";
    // otherwise show a generic message and log the details server-side only.
    res.render("error-template", {
        error: err,
        stack: err.stack
    });
};

module.exports = { errorHandler };
