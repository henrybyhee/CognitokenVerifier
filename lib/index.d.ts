import { IAccessTokenPayload, IIdTokenPayload } from "./interfaces";
export declare class CognitokenVerifyService {
    private appId;
    private cache;
    private issuer;
    constructor(appId: string, userPoolId: string);
    /**
     * verify function invokes 3 steps verification pipeline for token generated from
     * AWS Cognito. Validation is performed according to documentation
     * https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
     *
     * @param token Token in use.
     */
    verify(token: string): Promise<IAccessTokenPayload | IIdTokenPayload>;
    /**
     * Get Public Keys from cachce, else Call API to minimize network calls.
     */
    private getUserPoolPublicKeys;
}
