export interface IRSAMap {
  key: string;
  buffer: Buffer;
}

export interface IHeader {
  kid: string;
  alg: string;
}
export interface IPayload {
  at_hash?: string;
  sub: string;
  aud?: string;
  email_verified?: boolean;
  event_id?: string;
  token_use: string;
  auth_time: number;
  iss: string;
  "cognito:username"?: string;
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
