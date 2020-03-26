"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class CognitokenError extends Error {
    constructor(type, message) {
        super(message);
        Object.setPrototypeOf(this, CognitokenError.prototype);
        this.type = type;
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.CognitokenError = CognitokenError;
