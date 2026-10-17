//! Closed company routes. Credentials and signing remain owned by Accounts.
use crate::ClientError;
use http::Method;

pub enum CompanyRequest {
    Overview,
    Members { after: Option<String> },
    Invitations { after: Option<String> },
    Invite(Vec<u8>),
    Revoke { id: String, body: Vec<u8> },
    ChangeMember { id: String, body: Vec<u8> },
}
impl CompanyRequest {
    pub(crate) fn prepare(self) -> Result<(Method, String, Option<Vec<u8>>), ClientError> {
        let (method, path, body) = match self {
            Self::Overview => (Method::GET, "/v2/company".into(), None),
            Self::Members { after } => (Method::GET, page("members", after)?, None),
            Self::Invitations { after } => (Method::GET, page("invitations", after)?, None),
            Self::Invite(body) => (Method::POST, "/v2/company/invitations".into(), Some(body)),
            Self::Revoke { id, body } => {
                identifier(&id)?;
                (
                    Method::POST,
                    format!("/v2/company/invitations/{id}/revoke"),
                    Some(body),
                )
            }
            Self::ChangeMember { id, body } => {
                identifier(&id)?;
                (
                    Method::POST,
                    format!("/v2/company/members/{id}"),
                    Some(body),
                )
            }
        };
        if body
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > 4096)
        {
            return Err(ClientError::InvalidInput);
        }
        Ok((method, path, body))
    }
}
fn identifier(id: &str) -> Result<(), ClientError> {
    if crate::valid_id(id) && id.len() <= 128 {
        Ok(())
    } else {
        Err(ClientError::InvalidInput)
    }
}
fn page(resource: &str, after: Option<String>) -> Result<String, ClientError> {
    match after {
        Some(after) => {
            identifier(&after)?;
            Ok(format!("/v2/company/{resource}?after={after}"))
        }
        None => Ok(format!("/v2/company/{resource}")),
    }
}
pub(crate) fn route_template(path: &str) -> Option<&'static str> {
    if path.starts_with("/v2/company/invitations/") {
        Some("/v2/company/invitations/{invitation_id}/revoke")
    } else if path.starts_with("/v2/company/members/") {
        Some("/v2/company/members/{user_id}")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_reject_path_query_injection_and_unbounded_bodies() {
        for id in ["", "../other", "user?after=x", "a/b", "%2f", "a#b"] {
            assert!(
                CompanyRequest::Members {
                    after: Some(id.into())
                }
                .prepare()
                .is_err()
            );
            assert!(
                CompanyRequest::ChangeMember {
                    id: id.into(),
                    body: vec![1]
                }
                .prepare()
                .is_err()
            );
        }
        assert!(CompanyRequest::Invite(vec![1; 4097]).prepare().is_err());
        assert_eq!(
            CompanyRequest::Members {
                after: Some("user_1".into())
            }
            .prepare()
            .unwrap()
            .1,
            "/v2/company/members?after=user_1"
        );
        assert_eq!(
            route_template("/v2/company/invitations/private/revoke"),
            Some("/v2/company/invitations/{invitation_id}/revoke")
        );
    }
}
