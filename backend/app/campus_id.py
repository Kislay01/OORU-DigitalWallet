"""Campus ID credential definition shared by issuer, wallet and verifier.

Mirrors shared/campus-id.schema.json.
"""

VCT = "CampusID"
FORMAT = "vc+sd-jwt"
CONFIGURATION_ID = "CampusID_SD_JWT"

ALWAYS_VISIBLE = ("credential_id",)
DISCLOSABLE = ("name", "roll_number", "branch", "enrollment_status", "valid_until", "photo")
REQUIRED = ("credential_id", "name", "roll_number", "branch", "enrollment_status", "valid_until")

ENROLLMENT_STATUSES = ("active", "graduated", "suspended")

DISPLAY_NAMES = {
    "credential_id": "Credential ID",
    "name": "Full name",
    "roll_number": "Roll number",
    "branch": "Branch",
    "enrollment_status": "Enrollment status",
    "valid_until": "Valid until",
    "photo": "Photo",
}
