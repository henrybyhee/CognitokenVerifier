import jwt from "jsonwebtoken";
import jwkToPem = require("jwk-to-pem");
import request from "request";
import { promisify } from "util";
import { CognitokenError } from "./error";
import { IRSAToken, ICognitoJWKSet, IPayload, ICognitoJWK } from "./interfaces";

const composePromises = (initialValue: string, ...functions) => {
  return functions.reduce(
    (accum, func) => Promise.resolve(accum).then(func),
    initialValue
  );
};

const jwtVerifyPromise = promisify(jwt.verify);

/**
 * Step 1: Confirm the structure of JWT
 * @param token JWT token
 */
export const JWTStructuralCheck = (token: string) => {
  const isRight = token.split(".").length === 3;
  if (!isRight) {
    throw new CognitokenError(
      "JWTStructureError",
      "Token does not have 3 sections"
    );
  }
  return token;
};

/**
 * Step 2: Validate the JWT Signature.
 * Decode the token.
 * @param token JWT token.
 */
export const decodeJWT = (token: string) =>
  jwt.decode(token, { complete: true });

export const hasHeaderAndKID = (decoded: IRSAToken): IRSAToken => {
  if (!decoded) {
    throw new CognitokenError("JWTDecodeError", "JWT Token is not valid");
  }
  const { header } = decoded;
  if (!header) {
    throw new CognitokenError(
      "MissingHeaderError",
      "Token header is not found"
    );
  }
  const { kid } = header;
  if (!kid) {
    throw new CognitokenError(
      "MissingKIDError",
      "Token header does not contain KID"
    );
  }
  return decoded;
};

const selectJWKfromKeys = (jwkSet: ICognitoJWKSet) => (decoded: IRSAToken) => {
  const filteredKey = jwkSet.keys.filter(key => key.kid === decoded.header.kid);

  if (filteredKey.length === 0) {
    throw new CognitokenError("selectJWKfromKeys", "kid is not found on set");
  }
  return filteredKey[0];
};

const JWTSignatureValidate = (idToken: string) => (jwk: ICognitoJWK) => {
  const pem = jwkToPem(jwk);
  return jwtVerifyPromise(idToken, pem).catch((err: Error) => {
    throw new CognitokenError(err.name, err.message);
  });
};

/**
 * Step 3: Verify the claims
 * @param clientId Array of app client ids associated with User Pool
 * @param issuer Should match domain+user pool id
 * @param timeNow UTC time now
 * @param accessType 'id' or 'access'
 */
const JWTClaimVerify = (
  clientIds: string[],
  issuer: string,
  timeNow: number,
  accessType: string
) => (payload: IPayload) => {
  const condition =
    clientIds.reduce((prev, curr) => prev || payload.aud === curr, false) &&
    payload.iss === issuer &&
    payload.exp > timeNow &&
    payload.token_use === accessType;
  if (!condition) {
    throw new CognitokenError(
      "ClaimVerifyError",
      "Verification failed: Wrong aud, iss or exp"
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
   * @param {string[]} appId app client ID
   * @param {string} issuer Issuer https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>
   * @param {Array} JwkSet unique public key for every user pool, retrievable at issuer/.well-known/jwks.json
   */
  public appId: string[];
  public issuer: string;
  public jwkSet!: ICognitoJWKSet;
  constructor(appId: string[], issuer: string, jwkSet?: ICognitoJWKSet) {
    this.appId = appId;
    this.issuer = issuer;
    this.getJWKIfUndefined(jwkSet)
      .then(jwk => (this.jwkSet = jwk))
      .catch(err => console.log(err));
  }

  public getJWKIfUndefined(
    jwkset: ICognitoJWKSet | undefined
  ): Promise<ICognitoJWKSet> {
    return new Promise<any>((resolve, reject) => {
      if (jwkset) {
        resolve(jwkset);
      } else {
        request(
          `${this.issuer}/.well-known/jwks.json`,
          (err, response, body) => {
            if (err || response.statusCode !== 200) {
              reject(`Cannot retrieve jwk set from server ${err}`);
            } else {
              resolve(JSON.parse(body));
            }
          }
        );
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
  public verify(token: string, use: string): Promise<IPayload> {
    const timeNow = new Date().getTime() / 1000;

    return this.getJWKIfUndefined(this.jwkSet).then(jwkset =>
      composePromises(
        token,
        JWTStructuralCheck,
        decodeJWT,
        hasHeaderAndKID,
        selectJWKfromKeys(jwkset),
        JWTSignatureValidate(token),
        JWTClaimVerify(this.appId, this.issuer, timeNow, use)
      )
    );
  }
}
