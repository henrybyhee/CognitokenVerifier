export interface ITokenPayload {
  sub: string;
  event_id: string;
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  iat: number;
}

export interface IAccessTokenPayload extends ITokenPayload {
  scope: string;
  jti: string;
  client_id: string;
  username: string;
}

export interface IIdTokenPayload extends ITokenPayload {
  email_verified: boolean;
  phone_number_verified: boolean;
  aud: string;
  name: string;
  phone_number: string;
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
  keys: ICognitoJWK[];
}

export interface IJwtHeader {
  kid: string;
  alg: string;
}

export interface ICognitoJwt {
  header: IJwtHeader;
  payload: IAccessTokenPayload | IIdTokenPayload;
  signature: string;
}
