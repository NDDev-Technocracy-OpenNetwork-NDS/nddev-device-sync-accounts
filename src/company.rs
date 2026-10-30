//! Closed organization routes. Original credentials/signing remain in Accounts.
use crate::{ClientError, organizations_wire as dto};
use http::Method;

pub enum CompanyRequest {
    Organizations,
    Create(Vec<u8>),
    Scoped {
        company: String,
        revision: u64,
        operation: CompanyOperation,
    },
}
pub enum CompanyOperation {
    Overview,
    Members { after: Option<String> },
    Invitations { after: Option<String> },
    Invite(Vec<u8>),
    Revoke { id: String, body: Vec<u8> },
    ChangeMember { id: String, body: Vec<u8> },
}
impl CompanyRequest {
    pub(crate) fn prepare(self) -> Result<(Method, String, Option<Vec<u8>>), ClientError> {
        match self {
            Self::Organizations => Ok((Method::GET, "/v3/organizations".into(), None)),
            Self::Create(body) => {
                bounded(&body)?;
                let _: dto::OrganizationCreateRequest = decode(&body)?;
                Ok((Method::POST, "/v3/organizations".into(), Some(body)))
            }
            Self::Scoped {
                company,
                revision,
                operation,
            } => {
                identifier(&company)?;
                if !(1..=nddev_device_sync_domain::sync::MAX_REVISION).contains(&revision) {
                    return Err(ClientError::InvalidInput);
                }
                let base = format!("/v3/organizations/{company}");
                let (resource, after) = match operation {
                    CompanyOperation::Overview => ("", None),
                    CompanyOperation::Members { after } => ("/members", after),
                    CompanyOperation::Invitations { after } => ("/invitations", after),
                    CompanyOperation::Invite(body) => {
                        bounded(&body)?;
                        let value: dto::OrganizationInvitationRequest = decode(&body)?;
                        return command(
                            base + "/invitations",
                            body,
                            value.membership_revision,
                            revision,
                        );
                    }
                    CompanyOperation::Revoke { id, body } => {
                        identifier(&id)?;
                        bounded(&body)?;
                        let value: dto::OrganizationRevokeRequest = decode(&body)?;
                        return command(
                            format!("{base}/invitations/{id}/revoke"),
                            body,
                            value.membership_revision,
                            revision,
                        );
                    }
                    CompanyOperation::ChangeMember { id, body } => {
                        identifier(&id)?;
                        bounded(&body)?;
                        let value: dto::OrganizationMemberChangeRequest = decode(&body)?;
                        return command(
                            format!("{base}/members/{id}"),
                            body,
                            value.membership_revision,
                            revision,
                        );
                    }
                };
                let mut path = format!("{base}{resource}?membership_revision={revision}");
                if let Some(after) = after {
                    identifier(&after)?;
                    path.push_str("&after=");
                    path.push_str(&after);
                }
                Ok((Method::GET, path, None))
            }
        }
    }
}
fn command(
    path: String,
    body: Vec<u8>,
    captured: i64,
    revision: u64,
) -> Result<(Method, String, Option<Vec<u8>>), ClientError> {
    if u64::try_from(captured).ok() != Some(revision) {
        return Err(ClientError::InvalidInput);
    }
    // The exact original bytes, including captured revision, are signed.
    // Never rewrite a retry's payload or membership epoch.
    Ok((Method::POST, path, Some(body)))
}
fn bounded(body: &[u8]) -> Result<(), ClientError> {
    if body.is_empty() || body.len() > 4096 {
        Err(ClientError::InvalidInput)
    } else {
        Ok(())
    }
}
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ClientError> {
    serde_json::from_slice(body).map_err(|_| ClientError::InvalidInput)
}
fn identifier(id: &str) -> Result<(), ClientError> {
    if crate::valid_id(id) && id.len() <= 128 && !matches!(id, "." | "..") {
        Ok(())
    } else {
        Err(ClientError::InvalidInput)
    }
}
pub(crate) fn route_template(path: &str) -> Option<&'static str> {
    let path = path.split('?').next()?;
    if path == "/v3/organizations" {
        return Some("/v3/organizations");
    }
    let parts = path
        .strip_prefix("/v3/organizations/")?
        .split('/')
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [_] => Some("/v3/organizations/{company_id}"),
        [_, "members"] => Some("/v3/organizations/{company_id}/members"),
        [_, "invitations"] => Some("/v3/organizations/{company_id}/invitations"),
        [_, "members", _] => Some("/v3/organizations/{company_id}/members/{user_id}"),
        [_, "invitations", _, "revoke"] => {
            Some("/v3/organizations/{company_id}/invitations/{invitation_id}/revoke")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scoped(company: &str, revision: u64, operation: CompanyOperation) -> CompanyRequest {
        CompanyRequest::Scoped {
            company: company.into(),
            revision,
            operation,
        }
    }
    #[test]
    fn scoped_routes_reject_injection_and_preserve_the_captured_revision() {
        for id in [
            "",
            ".",
            "..",
            "../other",
            "user?after=x",
            "a/b",
            "%2f",
            "a#b",
        ] {
            assert!(scoped(id, 4, CompanyOperation::Overview).prepare().is_err());
            assert!(
                scoped(
                    "company",
                    4,
                    CompanyOperation::Members {
                        after: Some(id.into())
                    }
                )
                .prepare()
                .is_err()
            );
            assert!(
                scoped(
                    "company",
                    4,
                    CompanyOperation::ChangeMember {
                        id: id.into(),
                        body: vec![1]
                    }
                )
                .prepare()
                .is_err()
            );
        }
        for revision in [
            0,
            nddev_device_sync_domain::sync::MAX_REVISION + 1,
            u64::MAX,
        ] {
            assert!(
                scoped("company", revision, CompanyOperation::Overview)
                    .prepare()
                    .is_err()
            );
        }
        assert_eq!(
            scoped(
                "company",
                4,
                CompanyOperation::Members {
                    after: Some("user_1".into())
                }
            )
            .prepare()
            .unwrap()
            .1,
            "/v3/organizations/company/members?membership_revision=4&after=user_1"
        );
        assert_eq!(
            route_template("/v3/organizations/private/members/user?membership_revision=4"),
            Some("/v3/organizations/{company_id}/members/{user_id}")
        );
    }
    #[test]
    fn command_body_cannot_be_rebound_to_another_membership_or_normalized() {
        let original=br#" {"membership_revision":4,"payload":{"operation_id":"01900000-0000-7000-8000-000000000001"}} "#.to_vec();
        let result = scoped(
            "company",
            4,
            CompanyOperation::Revoke {
                id: "A".repeat(43),
                body: original.clone(),
            },
        )
        .prepare()
        .unwrap();
        assert_eq!(result.0, Method::POST);
        assert_eq!(result.2, Some(original.clone()));
        assert!(
            scoped(
                "company",
                5,
                CompanyOperation::Revoke {
                    id: "A".repeat(43),
                    body: original
                }
            )
            .prepare()
            .is_err()
        );
        for body in [
            vec![1; 4097],
            br#"{"payload":{"operation_id":"id"}}"#.to_vec(),
            br#"{"membership_revision":4,"payload":{"operation_id":"id","tenant_id":"injected"}}"#
                .to_vec(),
        ] {
            assert!(
                scoped(
                    "company",
                    4,
                    CompanyOperation::Revoke {
                        id: "A".repeat(43),
                        body
                    }
                )
                .prepare()
                .is_err()
            );
        }
        assert!(
            CompanyRequest::Create(
                br#"{"operation_id":"id","display_name":"name","role":"admin"}"#.to_vec()
            )
            .prepare()
            .is_err()
        );
    }
}
