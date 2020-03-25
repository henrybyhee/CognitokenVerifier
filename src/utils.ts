import {
  ICognitoJWKSet,
  ICognitoJwt,
  IJwtHeader,
  IAccessTokenPayload,
  IIdTokenPayload
} from "./interfaces";
import jwt from "jsonwebtoken";
import { CognitokenError } from "./error";
import jwkToPem = require("jwk-to-pem");

/**
 * Step 1: Ensure that token has 3 sections, separated by '.'
 * @param token token in use.
 */
export const hasThreeSections = (token: string): boolean =>
  token.split(".").length === 3;

/**
 * Step 2: Validate Jwt Signature.
 * @param token token in use.
 * @param publicKeys JWK prublic keys of this User pool
 */
export const validateCognitoJwtSignature = (
  token: string,
  publicKeys: ICognitoJWKSet
): Promise<IAccessTokenPayload | IIdTokenPayload> => {
  const decoded = jwt.decode(token, { complete: true });
  if (decoded == null) {
    throw new CognitokenError(
      "validateCognitoJwtSignatureError",
      "JWT Token is not valid"
    );
  }
  const { header } = decoded as ICognitoJwt;
  if (header == null) {
    throw new CognitokenError(
      "validateCognitoJwtSignatureError",
      "header is not found in decoded payload"
    );
  }
  const { kid } = header as IJwtHeader;
  if (kid == null) {
    throw new CognitokenError(
      "validateCognitoJwtSignatureError",
      "Key ID is missing in decoded header"
    );
  }

  // Search for public key with matching Key ID
  const signingPublicKey = publicKeys.keys.find(pubKey => pubKey.kid === kid);
  if (signingPublicKey == null) {
    throw new CognitokenError(
      "validateCognitoJwtSignatureError",
      `No matching pubic key found with Key Id (${kid}) in token.`
    );
  }

  // Verify JWT
  const pem = jwkToPem(signingPublicKey);

  return new Promise(resolve => {
    jwt.verify(token, pem, { algorithms: ["RS256"] }, (err, payload) => {
      if (err) {
        throw new CognitokenError(err.name, err.message);
      }
      if (typeof payload === "string") {
        throw new CognitokenError("VerifyJWTError", `Payload is a string`);
      }
      resolve(payload as IAccessTokenPayload | IIdTokenPayload);
    });
  });
};

/**
 * Step 3: Verify the JWT payload claims.
 * @param appId App Client ID created in User Pool
 * @param issuer The issuer (iss) claim should match your user pool.
 */
export const verifyClaims = (
  appId: string,
  issuer: string,
  payload: IAccessTokenPayload | IIdTokenPayload
) => {
  const timeNowInSeconds = new Date().getTime() / 1000;
  switch (payload.token_use) {
    case "id": {
      const idToken = payload as IIdTokenPayload;
      return (
        idToken.aud === appId &&
        idToken.iss === issuer &&
        timeNowInSeconds < idToken.exp
      );
    }
    case "access": {
      const accessToken = payload as IAccessTokenPayload;
      return accessToken.iss === issuer && timeNowInSeconds < accessToken.exp;
    }
    default:
      throw new CognitokenError(
        "Invalid token use",
        `Invalid token use: ${payload.token_use}`
      );
  }
};

export const buildIssuer = (userPoolId: string): string => {
  const regionId = userPoolId.split("_")[0];
  return `https://cognito-idp.${regionId}.amazonaws.com/${userPoolId}`;
};
