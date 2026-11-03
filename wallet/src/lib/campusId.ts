export const VCT = "CampusID";
export const FORMAT = "vc+sd-jwt";
export const CONFIGURATION_ID = "CampusID_SD_JWT";

export const FIELD_LABELS: Record<string, string> = {
  name: "Full name",
  roll_number: "Roll number",
  branch: "Branch",
  enrollment_status: "Enrollment status",
  valid_until: "Valid until",
  photo: "Photo",
};

export const FIELD_ORDER = ["name", "roll_number", "branch", "enrollment_status", "valid_until", "photo"];

export interface CampusIdClaims {
  name?: string;
  roll_number?: string;
  branch?: string;
  enrollment_status?: string;
  valid_until?: string;
  photo?: string;
}

export interface StoredCredential {
  id: string; // credential_id
  sdJwt: string; // issuer JWT + all disclosures, as received
  issuer: string;
  claims: CampusIdClaims;
  statusUrl?: string;
  issuedAt: number;
  expiresAt: number;
  receivedAt: number;
  lastStatus?: { status: string; checkedAt: number };
}
