export class CognitokenError extends Error {

    private type: string;

    constructor(type: string, message: string) {
        super(message);
        Object.setPrototypeOf(this, CognitokenError.prototype);
        this.type = type;
        Error.captureStackTrace(this, this.constructor);
    }
}