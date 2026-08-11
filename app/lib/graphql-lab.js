"use strict";

/*
 * Deliberately minimal "GraphQL-style" query resolver mounted at POST /api/graphql
 * (app/routes/api.js). It is not built on the real graphql-js engine - it exists to
 * demonstrate the Hardening gaps that show up in real GraphQL deployments so a
 * scanner/tester can exercise them without needing network access to install
 * additional packages:
 *
 *   1. Introspection is left enabled (a "__schema" query returns the full schema,
 *      including sensitive field names such as password/ssn/bankAcc), which in a
 *      real deployment should be disabled outside of development.
 *   2. There is no query depth/complexity limiting - "friend" is a recursive field
 *      that can be nested arbitrarily deep, allowing a resource-exhaustion (DoS)
 *      query.
 *   3. There is no field-level or object-level authorization: any authenticated
 *      user can request any other user's sensitive fields by id (BOLA at the
 *      GraphQL layer, same underlying bug as the REST IDOR endpoints, different
 *      transport).
 *
 * Query shape (JSON, not the textual GraphQL language, to avoid needing a parser):
 *   { "query": "__schema" }
 *   { "query": "user", "args": { "id": 1 }, "fields": ["userName", "ssn", "bankAcc"] }
 *   { "query": "user", "args": { "id": 1 }, "fields": ["userName"],
 *     "nested": { "field": "friend", "args": { "id": 2 }, "fields": [...], "nested": {...} } }
 */

const SCHEMA = {
    User: ["_id", "userName", "firstName", "lastName", "password", "ssn", "dob", "address",
        "bankAcc", "bankRouting", "isAdmin", "friend"],
    queries: ["user", "users", "__schema"]
};

const resolveUser = (usersCol, id, fields, nested, callback) => {
    usersCol.findOne({ _id: parseInt(id, 10) }, (err, user) => {
        if (err || !user) return callback(null);

        // No authorization check here: the caller only needs to be logged in
        // (enforced by the route), not to own or be related to this record.
        const projected = {};
        fields.forEach((f) => {
            if (Object.prototype.hasOwnProperty.call(user, f)) projected[f] = user[f];
        });

        if (nested && nested.field === "friend" && nested.args) {
            return resolveUser(usersCol, nested.args.id, nested.fields || [], nested.nested, (friend) => {
                projected.friend = friend;
                return callback(projected);
            });
        }

        return callback(projected);
    });
};

const execute = (db, body, callback) => {
    const usersCol = db.collection("users");
    const { query, args, fields, nested } = body || {};

    if (query === "__schema") {
        // Introspection enabled unconditionally - discloses sensitive field names.
        return callback(null, { data: { __schema: SCHEMA } });
    }

    if (query === "user" && args && args.id !== undefined) {
        return resolveUser(usersCol, args.id, fields || [], nested, (user) => {
            return callback(null, { data: { user } });
        });
    }

    if (query === "users") {
        // No pagination limit either - full table scan/response on demand.
        return usersCol.find({}).toArray((err, users) => {
            if (err) return callback(err, null);
            const projected = users.map((user) => {
                const out = {};
                (fields || []).forEach((f) => {
                    if (Object.prototype.hasOwnProperty.call(user, f)) out[f] = user[f];
                });
                return out;
            });
            return callback(null, { data: { users: projected } });
        });
    }

    return callback(null, { errors: [{ message: `Unknown query '${query}'` }] });
};

module.exports = { execute, SCHEMA };
