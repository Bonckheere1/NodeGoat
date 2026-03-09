const { ReportsDAO } = require("../data/reports-dao");
const { environmentalScripts } = require("../../config/config");

function ReportsHandler() {
    "use strict";

    const reportsDAO = new ReportsDAO();

    this.displayReports = (req, res, next) => {
        const { userId } = req.session;

        return res.render("payroll", {
            userId,
            employees: null,
            searchName: "",
            environmentalScripts
        });
    };

    /*
     * A1 - SQL Injection
     * The search term from req.query.name is passed directly to ReportsDAO.searchEmployees
     * which concatenates it into a raw SQL string.
     *
     * Attack: search for  ' OR '1'='1  to dump all records.
     * Attack: search for  ' UNION SELECT id,username,password,salary,0 FROM users--
     *         to exfiltrate the users table via a UNION-based injection.
     *
     * Fix: sanitize/validate input before passing to DAO, or use parameterized
     *      queries in the DAO layer (see comments in reports-dao.js).
     */
    this.searchEmployees = (req, res, next) => {
        const { userId } = req.session;
        // Insecure: raw query parameter forwarded to DAO without sanitization
        const searchName = req.query.name || "";

        reportsDAO.searchEmployees(searchName, (err, employees) => {
            if (err) {
                // Surface the raw DB error so attackers can observe schema info (A6)
                return res.render("payroll", {
                    userId,
                    employees: [],
                    searchName,
                    dbError: err.message,
                    environmentalScripts
                });
            }

            return res.render("payroll", {
                userId,
                employees,
                searchName,
                environmentalScripts
            });
        });
    };

    /*
     * A1 - SQL Injection (second-order / numeric injection)
     * The :id URL parameter is interpolated directly into a SQL query in the DAO.
     *
     * Attack: GET /reports/employee/0 UNION SELECT id,username,password,salary,0 FROM users--
     */
    this.getEmployee = (req, res, next) => {
        const { userId } = req.session;
        // Insecure: raw URL parameter passed to DAO without parseInt or validation
        const empId = req.params.id;

        reportsDAO.getEmployeeById(empId, (err, employee) => {
            if (err) {
                return res.render("payroll", {
                    userId,
                    employees: [],
                    searchName: "",
                    dbError: err.message,
                    environmentalScripts
                });
            }

            return res.render("payroll", {
                userId,
                employees: employee ? [employee] : [],
                searchName: "",
                environmentalScripts
            });
        });
    };
}

module.exports = ReportsHandler;
