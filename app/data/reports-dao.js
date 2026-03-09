/*
 * A1 - SQL Injection
 *
 * This module demonstrates SQL Injection vulnerabilities in a SQLite-backed
 * payroll reports feature. User-supplied input is concatenated directly into
 * SQL query strings instead of using parameterized queries.
 *
 * Attack examples:
 *   Search name: ' OR '1'='1       -> dumps all employee records
 *   Search name: ' OR 1=1--        -> bypasses filtering
 *   Search name: '; DROP TABLE employees;-- -> destructive injection
 *   Search name: ' UNION SELECT id,username,password,salary,0 FROM users-- -> data exfil
 */

const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// Use an in-memory database pre-seeded with sample payroll data
let dbInstance = null;

function getDb() {
    if (dbInstance) return dbInstance;

    dbInstance = new sqlite3.Database(":memory:");

    dbInstance.serialize(() => {
        // Create employees table with sensitive payroll data
        dbInstance.run(`
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                salary INTEGER NOT NULL,
                ssn TEXT NOT NULL
            )
        `);

        // Create a shadow users table (exfiltrable via UNION injection)
        dbInstance.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                salary INTEGER,
                is_admin INTEGER DEFAULT 0
            )
        `);

        // Seed employees
        const employees = [
            ["Alice Johnson", "Engineering", 95000, "123-45-6789"],
            ["Bob Smith", "Marketing", 72000, "987-65-4321"],
            ["Carol White", "HR", 68000, "456-78-9012"],
            ["David Brown", "Finance", 88000, "321-54-9876"],
            ["Eve Davis", "Engineering", 102000, "654-32-1098"]
        ];
        const insertEmp = dbInstance.prepare(
            "INSERT INTO employees (name, department, salary, ssn) VALUES (?, ?, ?, ?)"
        );
        employees.forEach(e => insertEmp.run(e));
        insertEmp.finalize();

        // Seed users (simulates credential store accessible via UNION injection)
        const users = [
            [1, "admin", "s3cr3tAdmin!", 0, 1],
            [2, "user1", "Password123", 95000, 0],
            [3, "user2", "qwerty", 72000, 0]
        ];
        const insertUser = dbInstance.prepare(
            "INSERT INTO users (id, username, password, salary, is_admin) VALUES (?, ?, ?, ?, ?)"
        );
        users.forEach(u => insertUser.run(u));
        insertUser.finalize();
    });

    return dbInstance;
}

/* ReportsDAO provides payroll search functionality */
function ReportsDAO() {
    "use strict";

    if (false === (this instanceof ReportsDAO)) {
        console.log("Warning: ReportsDAO constructor called without 'new' operator");
        return new ReportsDAO();
    }

    const db = getDb();

    /*
     * VULNERABLE: searchEmployees builds a query via string concatenation.
     * The `name` parameter comes directly from req.query.name with no
     * sanitization or parameterization, allowing classic SQL injection.
     *
     * Fix (A1): Use a parameterized query instead:
     *   const query = "SELECT id, name, department, salary FROM employees WHERE name LIKE ?";
     *   db.all(query, [`%${name}%`], callback);
     */
    this.searchEmployees = (name, callback) => {
        // Insecure: user input concatenated directly into SQL string
        const query = `SELECT id, name, department, salary FROM employees WHERE name LIKE '%${name}%'`;

        console.log(`[ReportsDAO] Executing query: ${query}`);

        db.all(query, (err, rows) => {
            if (err) {
                return callback(err, null);
            }
            return callback(null, rows);
        });
    };

    /*
     * VULNERABLE: getEmployeeById fetches a single employee by ID using
     * string interpolation. An attacker can inject UNION SELECT to exfiltrate
     * data from other tables.
     *
     * Payload: 0 UNION SELECT id, username, password, is_admin FROM users--
     *
     * Fix (A1): Use parameterized query:
     *   db.get("SELECT * FROM employees WHERE id = ?", [id], callback);
     */
    this.getEmployeeById = (id, callback) => {
        // Insecure: id from request URL parameter concatenated into query
        const query = `SELECT * FROM employees WHERE id = ${id}`;

        console.log(`[ReportsDAO] Executing query: ${query}`);

        db.get(query, (err, row) => {
            if (err) {
                return callback(err, null);
            }
            return callback(null, row);
        });
    };
}

module.exports = { ReportsDAO };
