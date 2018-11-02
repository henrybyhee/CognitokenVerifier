/// <reference types="node" />
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
    auth_time: number;
    iss: string;
    "cognito:username": string;
    exp: number;
    iat: number;
    email: string;
}
export interface ICognitoJWK {
    kid: string;
    alg: string;
    kty: string;
    e: string;
    n: string;
    use: string;
}
export interface ICognitoJWKSet {
    [key: string]: ICognitoJWK[];
}
export interface IRSAToken {
    header: IHeader;
    payload: IPayload;
    signature: string;
}
export declare class CognitokenVerifier {
    /**
     * Class implementation to verify JSON Web Token as described in
     *  https://docs.aws.amazon.com/cognito/latest/developerguide/
     *  amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
     *
     * @param {string[]} appId app client ID
     * @param {string} issuer Issuer https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>
     * @param {Array} JwkSet unique public key for every user pool, retrievable at issuer/.well-known/jwks.json
     */
    appId: string[];
    issuer: string;
    jwkSet: ICognitoJWKSet;
    constructor(appId: string[], issuer: string, jwkSet?: ICognitoJWKSet);
    getJWKIfUndefined(jwkset: ICognitoJWKSet | undefined): Promise<any>;
    /**
     * Executes the complete verification process
     * @param {string} token JSON token returned from Cognito Session
     * @param {string} use Either 'id' or 'access'
     *
     * @returns {Promise} onSuccess: returns decoded token, onFailure: returns CognitonError
     */
    verify(token: string, use: string): Promise<any>;
}
