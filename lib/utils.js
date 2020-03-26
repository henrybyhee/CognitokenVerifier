"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const error_1 = require("./error");
const jwkToPem = require("jwk-to-pem");
/**
 * Step 1: Ensure that token has 3 sections, separated by '.'
 * @param token token in use.
 */
exports.hasThreeSections = (token) => token.split(".").length === 3;
/**
 * Step 2: Validate Jwt Signature.
 * @param token token in use.
 * @param publicKeys JWK prublic keys of this User pool
 */
exports.validateCognitoJwtSignature = (token, publicKeys) => {
    const decoded = jsonwebtoken_1.default.decode(token, { complete: true });
    if (decoded == null) {
        throw new error_1.CognitokenError("validateCognitoJwtSignatureError", "JWT Token is not valid");
    }
    const { header } = decoded;
    if (header == null) {
        throw new error_1.CognitokenError("validateCognitoJwtSignatureError", "header is not found in decoded payload");
    }
    const { kid } = header;
    if (kid == null) {
        throw new error_1.CognitokenError("validateCognitoJwtSignatureError", "Key ID is missing in decoded header");
    }
    // Search for public key with matching Key ID
    const signingPublicKey = publicKeys.keys.find(pubKey => pubKey.kid === kid);
    if (signingPublicKey == null) {
        throw new error_1.CognitokenError("validateCognitoJwtSignatureError", `No matching pubic key found with Key Id (${kid}) in token.`);
    }
    // Verify JWT
    const pem = jwkToPem(signingPublicKey);
    return new Promise(resolve => {
        jsonwebtoken_1.default.verify(token, pem, { algorithms: ["RS256"] }, (err, payload) => {
            if (err) {
                throw new error_1.CognitokenError(err.name, err.message);
            }
            if (typeof payload === "string") {
                throw new error_1.CognitokenError("VerifyJWTError", `Payload is a string`);
            }
            resolve(payload);
        });
    });
};
/**
 * Step 3: Verify the JWT payload claims.
 * @param appId App Client ID created in User Pool
 * @param issuer The issuer (iss) claim should match your user pool.
 */
exports.verifyClaims = (appId, issuer, payload) => {
    const timeNowInSeconds = new Date().getTime() / 1000;
    switch (payload.token_use) {
        case "id": {
            const idToken = payload;
            return (idToken.aud === appId &&
                idToken.iss === issuer &&
                timeNowInSeconds < idToken.exp);
        }
        case "access": {
            const accessToken = payload;
            return accessToken.iss === issuer && timeNowInSeconds < accessToken.exp;
        }
        default:
            throw new error_1.CognitokenError("Invalid token use", `Invalid token use: ${payload.token_use}`);
    }
};
exports.buildIssuer = (userPoolId) => {
    const regionId = userPoolId.split("_")[0];
    return `https://cognito-idp.${regionId}.amazonaws.com/${userPoolId}`;
};
