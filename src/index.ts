import jwt from "jsonwebtoken";
import { promisify } from "util";
import { CognitokenError } from "./error";

export interface IRSAMap {
    key: string;
    buffer: Buffer;
}

export interface IHeader {
    kid: string;
    alg: string;
}
export interface IPayload {
    at_hash: string;
    sub: string;
    aud: string;
    email_verified: boolean;
    event_id: string;
    token_use: string;
    auth_time: Number;
    iss: string;
    "cognito:username": string;
    exp: number;
    iat: number;
    email: string;
}

export interface IRSAToken {
    header: IHeader;
    payload: IPayload;
    signature: string;
}

const composePromises = (
    initialValue: string,
    ...functions) => {
    functions.reduce(
        (accum, func) => Promise.resolve(accum).then(func),
        initialValue,
    );
};

const jwtVerifyPromise = promisify(jwt.verify);

const JWTStructuralCheck = (token: string) => {
    const isRight = token.split(".").length === 3;
    if (!isRight) {
        throw new CognitokenError("JWTStructureError", "Token does not have 3 sections");
    }
    return token;
};

const decodeJWT = (token: string) => jwt.decode(token, { complete: true });

const hasHeaderAndKID = (decoded: IRSAToken) => {
    if (!decoded) {
        throw new CognitokenError("JWTDecodeError", "JWT Token is not valid");
    }
    const { header } = decoded;
    if (!header) {
        throw new CognitokenError("MissingHeaderError", "Token header is not found");
    }
    const { kid } = header;
    if (!kid) {
        throw new CognitokenError("MissingKIDError", "Token header does not contain KID");
    }
    return decoded;
};

const retrieveBufferFromMap = (
    pemMap: IRSAMap[]) => (decoded: IRSAToken) => {
        const kid = decoded.header.kid;
        const { buffer } = pemMap.filter((map) => map.key === kid)[0];

        if (!buffer) {
            throw new CognitokenError("keyBufferMapError", "buffer is not found on the map");
        }

        return buffer;
    };

const JWTSignatureValidate = (idToken: string) => (pem: Buffer) => {
    return jwtVerifyPromise(idToken, pem, { algorithms: ["RS256"] })
        .catch((err: Error) => {
            throw new CognitokenError(err.name, err.message);
        });
};

const JWTClaimVerify = (
    clientId: string,
    issuer: string,
    timeNow: number,
    accessType: string) => (payload: IPayload) => {
        const condition = payload.aud === clientId &&
            payload.iss === issuer &&
            payload.exp > timeNow &&
            payload.token_use === accessType;
        if (!condition) {
            throw new CognitokenError(
                "ClaimVerifyError",
                "Verification failed: Wrong aud, iss or exp",
            );
        }
        return payload;
    };

export class CognitokenVerifier {
    /**
     * Class implementation to verify JSON Web Token as described in
     *  https://docs.aws.amazon.com/cognito/latest/developerguide/
     *  amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
     *
     * @param {string} appId app client ID
     * @param {string} issuer Issuer https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>
     * @param {Array} keyBufferMap Array consisting of associative map storing the kid
     * and file buffer converted from JSON Web Keys in PEM Format
     * ie: [{key: 'abcdef', buffer: <Buffer >}, {key: 'ghijk', buffer: <Buffer >}]
     */
    public appId: string;
    public issuer: string;
    public keyBufferMap: IRSAMap[];
    constructor(appId: string, issuer: string, keyBufferMap: IRSAMap[]) {
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
    public verify(token: string, use: string) {
        const timeNow = new Date().getTime() / 1000;
        return composePromises(
            token,
            JWTStructuralCheck,
            decodeJWT, hasHeaderAndKID,
            retrieveBufferFromMap(this.keyBufferMap),
            JWTSignatureValidate(token),
            JWTClaimVerify(this.appId, this.issuer, timeNow, use),
        );
    }
}
