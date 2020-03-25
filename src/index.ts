import request from "request";
import { CognitokenError } from "./error";
import { ICognitoJWKSet } from "./interfaces";
import {
  hasThreeSections,
  validateCognitoJwtSignature,
  verifyClaims,
  buildIssuer
} from "./utils";
import NodeCache from "node-cache";
import { IAccessTokenPayload, IIdTokenPayload } from "./interfaces";

export class CognitoVerifier {
  private appId: string;
  private cache: NodeCache;
  private issuer: string;

  constructor(appId: string, userPoolId: string) {
    this.appId = appId;
    this.cache = new NodeCache();
    this.issuer = buildIssuer(userPoolId);
  }

  /**
   * verifyCognitoJwt produces a function that verifies jwt generated from
   * AWS Cognito. Validation is performed according to documentation
   * https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
   *
   * @param token Token in use.
   */
  public async verifyToken(
    token: string
  ): Promise<IAccessTokenPayload | IIdTokenPayload> {
    if (!hasThreeSections(token)) {
      throw new CognitokenError(
        "JwtStructuralCheckError",
        "Token does not have three parts."
      );
    }

    try {
      const pubKeys = await this.getUserPoolPublicKeys();
      const payload = await validateCognitoJwtSignature(token, pubKeys);
      const isVerified = verifyClaims(this.appId, this.issuer, payload);
      if (!isVerified) {
        throw new CognitokenError(
          "VerifyClaimsError",
          "Wrong audience or issuer claim."
        );
      }
      return payload;
    } catch (err) {
      throw err;
    }
  }

  /**
   * Get Public Keys from cachce, else Call API to minimize network calls.
   */
  private getUserPoolPublicKeys(): Promise<ICognitoJWKSet> {
    return new Promise(resolve => {
      if (this.cache.has("PUBLIC_KEYS")) {
        const pubKeys = this.cache.get("PUBLIC_KEYS") as ICognitoJWKSet;
        resolve(pubKeys);
      } else {
        request(
          `${this.issuer}/.well-known/jwks.json`,
          (err, response, body) => {
            if (err || response.statusCode !== 200) {
              throw new CognitokenError(
                "GetUserPoolPublicKeysError",
                err.message
              );
            } else {
              const jwkSet = JSON.parse(body) as ICognitoJWKSet;
              this.cache.set("PUBLIC_KEYS", jwkSet);
              resolve(jwkSet);
            }
          }
        );
      }
    });
  }
}
