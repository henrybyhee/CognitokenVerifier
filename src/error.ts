export class CognitokenError extends Error {
  public type: string;

  constructor(type: string, message: string) {
    super(message);
    Object.setPrototypeOf(this, CognitokenError.prototype);
    this.type = type;
    Error.captureStackTrace(this, this.constructor);
  }
}
