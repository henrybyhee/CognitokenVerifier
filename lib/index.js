"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwkToPem = require("jwk-to-pem");
const request_1 = __importDefault(require("request"));
const util_1 = require("util");
const error_1 = require("./error");
const composePromises = (initialValue, ...functions) => {
    return functions.reduce((accum, func) => Promise.resolve(accum).then(func), initialValue);
};
const jwtVerifyPromise = util_1.promisify(jsonwebtoken_1.default.verify);
const JWTStructuralCheck = (token) => {
    const isRight = token.split(".").length === 3;
    if (!isRight) {
        throw new error_1.CognitokenError("JWTStructureError", "Token does not have 3 sections");
    }
    return token;
};
const decodeJWT = (token) => jsonwebtoken_1.default.decode(token, { complete: true });
const hasHeaderAndKID = (decoded) => {
    if (!decoded) {
        throw new error_1.CognitokenError("JWTDecodeError", "JWT Token is not valid");
    }
    const { header } = decoded;
    if (!header) {
        throw new error_1.CognitokenError("MissingHeaderError", "Token header is not found");
    }
    const { kid } = header;
    if (!kid) {
        throw new error_1.CognitokenError("MissingKIDError", "Token header does not contain KID");
    }
    return decoded;
};
const selectJWKfromKeys = (jwkSet) => (decoded) => {
    const filteredKey = jwkSet.keys.
        filter((key) => key.kid === decoded.header.kid);
    if (filteredKey.length === 0) {
        throw new error_1.CognitokenError("selectJWKfromKeys", "kid is not found on set");
    }
    return filteredKey[0];
};
const JWTSignatureValidate = (idToken) => (jwk) => {
    const pem = jwkToPem(jwk);
    return jwtVerifyPromise(idToken, pem)
        .catch((err) => {
        throw new error_1.CognitokenError(err.name, err.message);
    });
};
/**
 *
 * @param clientId Array of app client ids associated with User Pool
 * @param issuer Should match domain+user pool id
 * @param timeNow UTC time now
 * @param accessType 'id' or 'access'
 */
const JWTClaimVerify = (clientIds, issuer, timeNow, accessType) => (payload) => {
    const condition = clientIds.reduce((prev, curr) => prev || (payload.aud === curr), false) &&
        payload.iss === issuer &&
        payload.exp > timeNow &&
        payload.token_use === accessType;
    if (!condition) {
        throw new error_1.CognitokenError("ClaimVerifyError", "Verification failed: Wrong aud, iss or exp");
    }
    return payload;
};
class CognitokenVerifier {
    constructor(appId, issuer, jwkSet) {
        this.appId = appId;
        this.issuer = issuer;
        this.getJWKIfUndefined(jwkSet)
            .then((jwk) => this.jwkSet = jwk)
            .catch((err) => console.log(err));
    }
    getJWKIfUndefined(jwkset) {
        return new Promise((resolve, reject) => {
            if (jwkset) {
                resolve(jwkset);
            }
            else {
                console.log("Getting Jwkset from server");
                request_1.default(`${this.issuer}/.well-known/jwks.json`, (err, response, body) => {
                    if (err || response.statusCode !== 200) {
                        reject(`Cannot retrieve jwk set from server ${err}`);
                    }
                    else {
                        resolve(JSON.parse(body));
                    }
                });
            }
        });
    }
    /**
     * Executes the complete verification process
     * @param {string} token JSON token returned from Cognito Session
     * @param {string} use Either 'id' or 'access'
     *
     * @returns {Promise} onSuccess: returns decoded token, onFailure: returns CognitonError
     */
    verify(token, use) {
        const timeNow = new Date().getTime() / 1000;
        return this.getJWKIfUndefined(this.jwkSet)
            .then((jwkset) => composePromises(token, JWTStructuralCheck, decodeJWT, hasHeaderAndKID, selectJWKfromKeys(jwkset), JWTSignatureValidate(token), JWTClaimVerify(this.appId, this.issuer, timeNow, use)));
    }
}
exports.CognitokenVerifier = CognitokenVerifier;
