import "mocha";
import { expect } from "chai";
import { hasThreeSections, verifyClaims } from "./utils";
import { CognitokenError } from "./error";

describe("Test Step 1: Ensure JWT Structural Integrity", () => {
  it("Should return True if string has 3 parts", () => {
    const token = "AAA.BBBB.CCCC";
    expect(hasThreeSections(token)).equal(true);
  });

  it("Should return False if string has less than 3 parts", () => {
    const token = "AAA.BBB";
    expect(hasThreeSections(token)).equal(false);
  });
});

describe("Test Step 3: Verify Claim", () => {
  it("Should verify Access token payload.", () => {
    const payload = {
      sub: "User",
      event_id: "SignIn",
      token_use: "access",
      auth_time: 1585153143,
      iss: "Cognito",
      exp: Infinity,
      iat: 1585153143,
      scope: "cognito:signin",
      jti: "789-789-789",
      client_id: "CLIENT_ABC",
      username: "USER_ABC"
    };
    expect(verifyClaims("", "Cognito", payload)).equal(true);
  });

  it("Should verify Id Token payload", () => {
    const payload = {
      sub: "User",
      event_id: "SignIn",
      token_use: "id",
      auth_time: 1585153143,
      iss: "Cognito",
      exp: Infinity,
      iat: 1585153143,
      email_verified: true,
      phone_number_verified: true,
      aud: "RECIPIENT",
      name: "USER",
      phone_number: "123456",
      email: "example@gmail.com"
    };
    expect(verifyClaims("RECIPIENT", "Cognito", payload)).equal(true);
  });

  it("Should not verify if token is expired.", () => {
    const payload = {
      sub: "User",
      event_id: "SignIn",
      token_use: "access",
      auth_time: 1585153143,
      iss: "Cognito",
      exp: 1585153143,
      iat: 1585153143,
      scope: "cognito:signin",
      jti: "789-789-789",
      client_id: "CLIENT_ABC",
      username: "USER_ABC"
    };
    expect(verifyClaims("", "Cognito", payload)).equal(false);
  });

  it("Should throw error if token use is neither 'access' nor 'id'", () => {
    const payload = {
      sub: "User",
      event_id: "SignIn",
      token_use: "something",
      auth_time: 1585153143,
      iss: "Cognito",
      exp: 1585153143,
      iat: 1585153143,
      scope: "cognito:signin",
      jti: "789-789-789",
      client_id: "CLIENT_ABC",
      username: "USER_ABC"
    };

    expect(() => verifyClaims("", "Cognito", payload)).to.throw(
      CognitokenError
    );
  });
});
