const COMMON_PATTERNS = [
  "password",
  "senha",
  "qwerty",
  "admin",
  "administrator",
  "letmein",
  "welcome",
  "123456",
  "company",
  "empresa"
];

function hasLongRepeat(value) {
  return /(.)\1{3,}/i.test(value);
}

function hasSequence(value) {
  const normalized = value.toLowerCase();
  const sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"];
  return sequences.some((sequence) => {
    for (let index = 0; index <= sequence.length - 5; index += 1) {
      if (normalized.includes(sequence.slice(index, index + 5))) return true;
    }
    return false;
  });
}

export function inspectPassword(password, identity = "") {
  const value = String(password || "");
  const normalized = value.toLowerCase();
  const identityLocal = String(identity || "").toLowerCase().split("@")[0];
  const flags = {
    commonPattern: COMMON_PATTERNS.some((pattern) => normalized.includes(pattern)),
    repeatedCharacters: hasLongRepeat(value),
    sequentialCharacters: hasSequence(value),
    containsIdentity: identityLocal.length >= 4 && normalized.includes(identityLocal)
  };

  const penalties =
    (flags.commonPattern ? 35 : 0) +
    (flags.repeatedCharacters ? 20 : 0) +
    (flags.sequentialCharacters ? 20 : 0) +
    (flags.containsIdentity ? 30 : 0);

  return {
    acceptable: penalties < 30,
    penalties: Math.min(penalties, 100),
    flags
  };
}
