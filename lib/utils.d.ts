import { ICognitoJWKSet, IAccessTokenPayload, IIdTokenPayload } from "./interfaces";
/**
 * Step 1: Ensure that token has 3 sections, separated by '.'
 * @param token token in use.
 */
export declare const hasThreeSections: (token: string) => boolean;
/**
 * Step 2: Validate Jwt Signature.
 * @param token token in use.
 * @param publicKeys JWK prublic keys of this User pool
 */
export declare const validateCognitoJwtSignature: (token: string, publicKeys: ICognitoJWKSet) => Promise<IAccessTokenPayload | IIdTokenPayload>;
/**
 * Step 3: Verify the JWT payload claims.
 * @param appId App Client ID created in User Pool
 * @param issuer The issuer (iss) claim should match your user pool.
 */
export declare const verifyClaims: (appId: string, issuer: string, payload: IAccessTokenPayload | IIdTokenPayload) => boolean;
export declare const buildIssuer: (userPoolId: string) => string;
