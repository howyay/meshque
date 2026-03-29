export function validateRoomCode(code: unknown): code is string {
  return typeof code === "string" && code.length >= 1 && code.length <= 256;
}

export function validatePeerId(id: unknown): id is string {
  return typeof id === "string" && id.length >= 1 && id.length <= 128;
}

export function validateCertFingerprint(fp: unknown): fp is string {
  return typeof fp === "string" && fp.length >= 1 && fp.length <= 512;
}

export function validateEndpoint(ep: unknown): ep is string {
  if (typeof ep !== "string") return false;
  // Basic format: host:port — allow IPv4, IPv6 (bracketed), and hostnames
  return /^(\[.+\]|[^:]+):\d{1,5}$/.test(ep);
}

export function validateNatType(t: unknown): t is "cone" | "symmetric" | "unknown" {
  return t === "cone" || t === "symmetric" || t === "unknown";
}
