"use strict";

const crypto = require("crypto");
const { HARDCODED_JWT_SECRET } = require("../data/lab-store");

/*
 * Minimal hand-rolled JWT-style token helper used by app/routes/api.js to
 * demonstrate Authentication & Session Management / Secrets & Cryptography
 * failures around token verification, without pulling in an external JWT
 * dependency.
 *
 * WARNING: Intentionally insecure. See the "verify" function below for the
 * headline bug: it trusts the attacker-controlled "alg" header instead of
 * pinning to a server-chosen algorithm (the class of bug behind CVE-2015-9235
 * and the classic "alg: none" JWT bypass).
 */

const b64url = (input) => Buffer.from(input).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const b64urlDecode = (input) => Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString();

const hmac = (data) => crypto.createHmac("sha256", HARDCODED_JWT_SECRET)
    .update(data)
    .digest("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Issues a token signed with a hardcoded, never-rotated secret and no "exp" claim,
// so tokens never expire.
const sign = (payload) => {
    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeader = b64url(JSON.stringify(header));
    const encodedPayload = b64url(JSON.stringify(payload));
    const signature = hmac(`${encodedHeader}.${encodedPayload}`);
    return `${encodedHeader}.${encodedPayload}.${signature}`;
};

// Verification bypass: the algorithm used to check the signature is read from the
// token itself. Sending a token with header {"alg":"none"} and an empty signature
// segment is accepted outright, letting an attacker forge arbitrary claims
// (e.g. {"userId":1,"isAdmin":true}) with no knowledge of any secret.
const verify = (token) => {
    const parts = (token || "").split(".");
    if (parts.length < 2) return { valid: false, payload: null };

    let header;
    let payload;
    try {
        header = JSON.parse(b64urlDecode(parts[0]));
        payload = JSON.parse(b64urlDecode(parts[1]));
    } catch (e) {
        return { valid: false, payload: null };
    }

    if (header.alg === "none") {
        return { valid: true, payload };
    }

    const expected = hmac(`${parts[0]}.${parts[1]}`);
    return { valid: expected === parts[2], payload };
};

module.exports = { sign, verify };
