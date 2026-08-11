/* The StatementDAO must be constructed with a connected database object */
function StatementDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof StatementDAO)) {
        console.log("Warning: StatementDAO constructor called without 'new' operator");
        return new StatementDAO(db);
    }

    const statementsCol = db.collection("statements");

    this.insert = (userId, fileName, notes, callback) => {

        const statement = {
            userId: parseInt(userId),
            fileName,
            notes,
            timestamp: new Date()
        };

        statementsCol.insert(statement, (err, result) => !err ? callback(null, result) : callback(err, null));
    };

    this.getAllForUser = (userId, filters, callback) => {
        const parsedUserId = parseInt(userId);
        const { search } = filters || {};

        const searchCriteria = () => {
            if (search) {
                /*
                 * VULNERABLE (A1 - NoSQL Injection): `search` is forwarded here
                 * from statement.js -> displayStatement, which reads it straight
                 * from req.query.search. It is concatenated into a MongoDB
                 * $where clause, which runs arbitrary JavaScript server-side
                 * against every document in the collection.
                 *
                 * Example payloads (as the `search` query string parameter):
                 *   ') || ('1'=='1                 -> dumps every user's statements, not just this account's
                 *   ');return(true);(this.notes||'  -> matches everything regardless of content
                 *   ');while(true){};('             -> denial of service, blocks the event loop
                 *
                 * Fix: never build $where from user input. Use a plain field
                 * match / $regex instead, e.g.:
                 *   return { userId: parsedUserId, notes: { $regex: escapeRegex(search) } };
                 */
                return {
                    $where: `this.userId == ${parsedUserId} && this.notes.indexOf('${search}') !== -1`
                };
            }
            return {
                userId: parsedUserId
            };
        };

        statementsCol.find(searchCriteria()).sort({
            timestamp: -1
        }).toArray((err, statements) => {
            if (err) return callback(err, null);
            return callback(null, statements || []);
        });
    };

    this.remove = (userId, fileName, callback) => {
        // Note: this only scopes by the *URL supplied* userId, not the
        // authenticated session user - see the missing ownership check in
        // statement.js -> deleteStatement.
        statementsCol.remove({
            userId: parseInt(userId),
            fileName
        }, err => callback(err, null));
    };

}

module.exports = { StatementDAO };
