"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var util_1 = require("util");
var error_1 = require("./error");
var composePromises = function (initialValue) {
    var functions = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        functions[_i - 1] = arguments[_i];
    }
    functions.reduce(function (accum, func) { return Promise.resolve(accum).then(func); }, initialValue);
};
var jwtVerifyPromise = util_1.promisify(jsonwebtoken_1.default.verify);
var JWTStructuralCheck = function (token) {
    var isRight = token.split(".").length === 3;
    if (!isRight) {
        throw new error_1.CognitokenError("JWTStructureError", "Token does not have 3 sections");
    }
    return token;
};
var decodeJWT = function (token) { return jsonwebtoken_1.default.decode(token, { complete: true }); };
var hasHeaderAndKID = function (decoded) {
    if (!decoded) {
        throw new error_1.CognitokenError("JWTDecodeError", "JWT Token is not valid");
    }
    var header = decoded.header;
    if (!header) {
        throw new error_1.CognitokenError("MissingHeaderError", "Token header is not found");
    }
    var kid = header.kid;
    if (!kid) {
        throw new error_1.CognitokenError("MissingKIDError", "Token header does not contain KID");
    }
    return decoded;
};
var retrieveBufferFromMap = function (pemMap) { return function (decoded) {
    var kid = decoded.header.kid;
    var buffer = pemMap.filter(function (map) { return map.key === kid; })[0].buffer;
    if (!buffer) {
        throw new error_1.CognitokenError("keyBufferMapError", "buffer is not found on the map");
    }
    return buffer;
}; };
var JWTSignatureValidate = function (idToken) { return function (pem) {
    return jwtVerifyPromise(idToken, pem, { algorithms: ["RS256"] })
        .catch(function (err) {
        throw new error_1.CognitokenError(err.name, err.message);
    });
}; };
var JWTClaimVerify = function (clientId, issuer, timeNow, accessType) { return function (payload) {
    var condition = payload.aud === clientId &&
        payload.iss === issuer &&
        payload.exp > timeNow &&
        payload.token_use === accessType;
    if (!condition) {
        throw new error_1.CognitokenError("ClaimVerifyError", "Verification failed: Wrong aud, iss or exp");
    }
    return payload;
}; };
var CognitokenVerifier = /** @class */ (function () {
    function CognitokenVerifier(appId, issuer, keyBufferMap) {
        this.keyBufferMap = keyBufferMap;
        this.appId = appId;
        this.issuer = issuer;
    }
    /**
     * Executes the complete verification process
     * @param {string} token JSON token returned from Cognito Session
     * @param {string} use Either 'id' or 'access'
     *
     * @returns {Promise} onSuccess: returns decoded token, onFailure: returns CognitonError
     */
    CognitokenVerifier.prototype.verify = function (token, use) {
        var timeNow = new Date().getTime() / 1000;
        return composePromises(token, JWTStructuralCheck, decodeJWT, hasHeaderAndKID, retrieveBufferFromMap(this.keyBufferMap), JWTSignatureValidate(token), JWTClaimVerify(this.appId, this.issuer, timeNow, use));
    };
    return CognitokenVerifier;
}());
exports.CognitokenVerifier = CognitokenVerifier;
