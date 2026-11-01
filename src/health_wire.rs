// Generated; do not edit. AGPL-3.0-only. NDDev OpenNetwork — https://nddev.ai
// Source: NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-protocol/contracts/v1/health-response.schema.json
// Schema SHA-256: a7eba30691dbdd30bd8adced052bd7ebf38ffb495dfe82f450a59c6cc0690d54
// Generator script SHA-256: ba71ce353a691d59227fbe948f45edf4b0667be7e5a105741f551d3186f6a8b8
// Tool: quicktype-core 26.0.0; dependency lock SHA-256: ec1d8541bcae0771e2fe0e95e572f60898fd62e6e31fbfbea80451d244aff5b9
// DTO generation is not schema, authorization or cryptographic validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub channel: String,

    pub database_configured: bool,

    pub module_count: i64,

    pub service: Service,

    pub source_commit: String,

    pub standards_release: String,

    pub status: Status,

    pub telemetry_enabled: bool,

    pub version: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Service {
    #[serde(rename = "nddev-device-sync-server")]
    NddevDeviceSyncServer,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[serde(rename = "ok")]
    StatusOk,
}
