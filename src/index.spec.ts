import "mocha";
import { expect, assert } from "chai";
import { JWTStructuralCheck, hasHeaderAndKID, decodeJWT } from "./index";
import { CognitokenError } from "./error";

describe("Test Step 1: Confirm the structure of JWT", () => {
  it("Should return token if it has 3 parts.", () => {
    const token =
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1ODUwNjYzMTEsImV4cCI6MTYxNjYwMjMxMSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.nncH3DlaaL0D9-VtkLX8lQNQQT8KCX6w6uuQoCe7JE0";
    expect(JWTStructuralCheck(token)).to.equal(token);
  });

  it("Should throw error if it has less than 3 parts", () => {
    const token = "";
    assert.throws(() => JWTStructuralCheck(token), CognitokenError);
  });
});

describe("Test Step 2: Validate JWT Signature", () => {
  it("Should return token if it has header and key Id.", () => {
    const decoded = {
      header: {
        alg: "RS256",
        kid: "EbbBy+6kFRMG4vvJRhbLeQnI4myic1qDKBTnbg8ykBU="
      },
      payload: {
        auth_time: 1000000,
        email: "hello@example.com",
        exp: 1000000,
        iat: 1000000,
        iss: "auth.example.com",
        sub: "Hello",
        token_use: "id"
      },
      signature: "Hello World"
    };
    expect(hasHeaderAndKID(decoded)).to.equal(decoded);
  });
});
