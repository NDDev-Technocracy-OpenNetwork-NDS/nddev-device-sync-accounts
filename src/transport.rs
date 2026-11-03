//! HTTP platform adapters. URL, credential and wire policies remain in the
//! shared identity client; neither adapter exposes a general authenticated proxy.
use crate::{ClientError, IdentityClient, WireRequest};
#[cfg(not(target_arch = "wasm32"))]
use crate::{SessionCredential, reply_limit};
use http::StatusCode;
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
pub(crate) mod browser;

impl IdentityClient {
    pub(crate) async fn transport_request(
        &self,
        options: WireRequest<'_>,
        propagation: HashMap<String, String>,
    ) -> Result<(StatusCode, Vec<u8>), ClientError> {
        #[cfg(target_arch = "wasm32")]
        {
            browser::request(&self.endpoint, options, propagation).await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let WireRequest {
                method,
                path,
                body,
                token,
                locale,
                signature,
            } = options;
            let mut request = self
                .http
                .request(
                    method,
                    self.endpoint
                        .join(path)
                        .map_err(|_| ClientError::InvalidEndpoint)?,
                )
                .header("accept-language", if locale == "ru" { "ru" } else { "en" });
            for (key, value) in propagation {
                request = request.header(key, value);
            }
            if let Some(SessionCredential::Bearer(token)) = token {
                request = request.bearer_auth(token.as_str());
            }
            if let Some(body) = body {
                request = request
                    .header(
                        "content-type",
                        match path {
                            "/v2/observability/events" => "application/x-ndjson",
                            "/v2/observability/traces" => "application/x-protobuf",
                            _ => "application/json",
                        },
                    )
                    .body(body);
            }
            if let Some(signature) = signature {
                request = request
                    .header("signature", signature.signature)
                    .header("signature-input", signature.signature_input)
                    .header("content-digest", signature.content_digest);
            }
            let mut response = request.send().await.map_err(|e| {
                if e.is_timeout() {
                    ClientError::Timeout
                } else {
                    ClientError::Transport
                }
            })?;
            let status = response.status();
            let limit = reply_limit(path);
            if response.content_length().is_some_and(|n| n > limit as u64) {
                return Err(ClientError::InvalidResponse);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| ClientError::Transport)? {
                if bytes.len() + chunk.len() > limit {
                    return Err(ClientError::InvalidResponse);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok((status, bytes))
        }
    }
}
