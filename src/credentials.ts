import { HandledError } from "./utils.js";

const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

interface TextFieldOptions {
  fieldNames: string[];
  label: string;
  required?: boolean;
}

interface SecretFieldOptions extends TextFieldOptions {
  encodedFieldNames: string[];
}

interface ProvidedString {
  provided: boolean;
  value?: string;
}

export interface ResolvedSecretValue {
  value?: string;
  sourceField?: string;
  encoded: boolean;
}

export interface ResolvedSshCredentials {
  username: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

export interface ResolvedOracleCredentials {
  username: string;
  password: string;
}

function isBlank(value: string | undefined): boolean {
  return !value || value.trim() === "";
}

function readProvidedString(
  args: Record<string, unknown>,
  fieldName: string,
): ProvidedString {
  if (!Object.hasOwn(args, fieldName)) {
    return {
      provided: false,
    };
  }

  const value = args[fieldName];
  if (value == null) {
    return {
      provided: true,
      value: undefined,
    };
  }

  if (typeof value !== "string") {
    throw new HandledError(
      "INVALID_ARGUMENT",
      `${fieldName} must be a string.`,
    );
  }

  return {
    provided: true,
    value,
  };
}

function invalidSecretError(label: string, reason: "blank" | "invalid"): HandledError {
  return new HandledError(
    "INVALID_ARGUMENT",
    reason === "blank"
      ? `The provided ${label} is missing or blank.`
      : `The provided ${label} is invalid.`,
  );
}

export function decodeEncodedSecret(encodedValue: string, label: string): string {
  const trimmed = encodedValue.trim();
  if (!trimmed) {
    throw invalidSecretError(label, "blank");
  }

  if (trimmed.length % 4 !== 0 || !BASE64_PATTERN.test(trimmed)) {
    throw invalidSecretError(label, "invalid");
  }

  const decodedBuffer = Buffer.from(trimmed, "base64");
  if (
    decodedBuffer.length === 0 ||
    decodedBuffer.toString("base64") !== trimmed
  ) {
    throw invalidSecretError(label, "invalid");
  }

  const decoded = decodedBuffer.toString("utf8");
  if (decoded.length === 0) {
    throw invalidSecretError(label, "blank");
  }

  return decoded;
}

export function resolvePreferredTextField(
  args: Record<string, unknown>,
  options: TextFieldOptions,
): string | undefined {
  for (const fieldName of options.fieldNames) {
    const candidate = readProvidedString(args, fieldName);
    if (!candidate.provided || isBlank(candidate.value)) {
      continue;
    }

    return candidate.value;
  }

  if (options.required) {
    throw new HandledError(
      "INVALID_ARGUMENT",
      `${options.label} is required and must be a non-empty string.`,
    );
  }

  return undefined;
}

export function resolvePreferredSecretField(
  args: Record<string, unknown>,
  options: SecretFieldOptions,
): ResolvedSecretValue {
  for (const fieldName of options.encodedFieldNames) {
    const candidate = readProvidedString(args, fieldName);
    if (!candidate.provided) {
      continue;
    }

    return {
      value: decodeEncodedSecret(candidate.value ?? "", options.label),
      sourceField: fieldName,
      encoded: true,
    };
  }

  const plainValue = resolvePreferredTextField(args, {
    fieldNames: options.fieldNames,
    label: options.label,
    required: options.required,
  });

  return {
    value: plainValue,
    sourceField: plainValue
      ? options.fieldNames.find((fieldName) => !isBlank(readProvidedString(args, fieldName).value))
      : undefined,
    encoded: false,
  };
}

export function resolveSshCredentials(
  args: Record<string, unknown>,
  authMethod: "password" | "privateKey" | "agent",
): ResolvedSshCredentials {
  const username =
    resolvePreferredTextField(args, {
      fieldNames: ["username", "hostUser", "ldapUser"],
      label: "username",
      required: true,
    }) ?? "";

  const password =
    authMethod === "password"
      ? resolvePreferredSecretField(args, {
          fieldNames: ["password", "hostPassword", "ldapPassword"],
          encodedFieldNames: [
            "passwordEncoded",
            "hostPasswordEncoded",
            "ldapPasswordEncoded",
          ],
          label: "SSH password",
          required: true,
        }).value
      : undefined;

  return {
    username,
    password,
    privateKey: resolvePreferredTextField(args, {
      fieldNames: ["privateKey"],
      label: "privateKey",
    }),
    passphrase: resolvePreferredTextField(args, {
      fieldNames: ["passphrase"],
      label: "passphrase",
    }),
  };
}

export function resolveSudoPassword(
  args: Record<string, unknown>,
): string | undefined {
  return resolvePreferredSecretField(args, {
    fieldNames: ["sudoPassword", "hostPassword", "password", "ldapPassword"],
    encodedFieldNames: [
      "sudoPasswordEncoded",
      "hostPasswordEncoded",
      "passwordEncoded",
      "ldapPasswordEncoded",
    ],
    label: "sudo password",
  }).value;
}

export function resolveOracleCredentials(
  args: Record<string, unknown>,
): ResolvedOracleCredentials {
  const username =
    resolvePreferredTextField(args, {
      fieldNames: ["username", "dbUser"],
      label: "username",
      required: true,
    }) ?? "";
  const password =
    resolvePreferredSecretField(args, {
      fieldNames: ["password", "dbPassword"],
      encodedFieldNames: ["passwordEncoded", "dbPasswordEncoded"],
      label: "Oracle DB password",
      required: true,
    }).value ?? "";

  return {
    username,
    password,
  };
}
