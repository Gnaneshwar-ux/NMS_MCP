import test from "node:test";
import assert from "node:assert/strict";

import {
  decodeEncodedSecret,
  resolveOracleCredentials,
  resolvePreferredSecretField,
  resolveSshCredentials,
  resolveSudoPassword,
} from "../dist/credentials.js";
import { HandledError } from "../dist/utils.js";

function encodeSecret(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

test("decodes a valid encoded secret", () => {
  assert.equal(
    decodeEncodedSecret(encodeSecret("Oracle1234"), "host password"),
    "Oracle1234",
  );
});

test("rejects an invalid encoded secret", () => {
  assert.throws(
    () => decodeEncodedSecret("not-base64", "host password"),
    (error) => {
      assert.ok(error instanceof HandledError);
      assert.equal(error.code, "INVALID_ARGUMENT");
      assert.equal(error.message, "The provided host password is invalid.");
      return true;
    },
  );
});

test("rejects blank and null encoded secrets", () => {
  assert.throws(
    () =>
      resolvePreferredSecretField(
        {
          hostPasswordEncoded: "",
        },
        {
          fieldNames: ["hostPassword"],
          encodedFieldNames: ["hostPasswordEncoded"],
          label: "host password",
        },
      ),
    /The provided host password is missing or blank\./,
  );

  assert.throws(
    () =>
      resolvePreferredSecretField(
        {
          hostPasswordEncoded: null,
        },
        {
          fieldNames: ["hostPassword"],
          encodedFieldNames: ["hostPasswordEncoded"],
          label: "host password",
        },
      ),
    /The provided host password is missing or blank\./,
  );
});

test("SSH credential resolution prefers the encoded host password", () => {
  const credentials = resolveSshCredentials(
    {
      hostUser: "nmsadmin",
      hostPassword: "legacy-plain-text",
      hostPasswordEncoded: encodeSecret("EncodedHostSecret"),
    },
    "password",
  );

  assert.equal(credentials.username, "nmsadmin");
  assert.equal(credentials.password, "EncodedHostSecret");
});

test("sudo credential resolution reuses the decoded host password", () => {
  assert.equal(
    resolveSudoPassword({
      hostPasswordEncoded: encodeSecret("EncodedHostSecret"),
      sudoPassword: "legacy-sudo",
    }),
    "EncodedHostSecret",
  );
});

test("DB credential resolution prefers the encoded DB password", () => {
  const credentials = resolveOracleCredentials({
    dbUser: "system",
    dbPassword: "legacy-db-password",
    dbPasswordEncoded: encodeSecret("EncodedDbSecret"),
  });

  assert.equal(credentials.username, "system");
  assert.equal(credentials.password, "EncodedDbSecret");
});
