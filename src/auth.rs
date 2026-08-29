use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header};
use eal_api_server::auth::{AuthPolicy, VerifiedActor, authorize_introspection};
use shared_auth_client::SharedAuthClient;

const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct WebAuthBoundary {
    client: SharedAuthClient,
    policy: AuthPolicy,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedActor {
    pub actor: VerifiedActor,
    pub bearer: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("identity authority unavailable")]
    Degraded,
    #[error("identity configuration invalid")]
    Configuration,
}

impl WebAuthBoundary {
    pub fn from_env() -> Result<Self, AuthError> {
        let base = required_env("SHARED_AUTH_BASE_URL")?;
        let service_credential = required_env("SHARED_AUTH_SERVICE_CREDENTIAL")?;
        if !strict_credential(&service_credential) {
            return Err(AuthError::Configuration);
        }
        let policy = AuthPolicy {
            issuer: required_env("SHARED_AUTH_ISSUER")?,
            audience: required_env("EAL_AUTH_AUDIENCE")?,
            authorized_client: required_env("EAL_AUTHORIZED_CLIENT")?,
            provider_tenant: required_env("EAL_PROVIDER_TENANT")?,
            product_tenant: required_env("EAL_PRODUCT_TENANT")?,
        };
        let client = SharedAuthClient::try_new(base)
            .map_err(|_| AuthError::Configuration)?
            .with_service_credential(service_credential)
            .with_max_response_bytes(64 * 1024);
        Ok(Self { client, policy })
    }

    pub async fn verify_request(
        &self,
        headers: &HeaderMap,
        required_scope: &str,
    ) -> Result<AuthenticatedActor, AuthError> {
        let bearer = request_bearer(headers)?.to_owned();
        let actor = self.verify_token(&bearer, required_scope).await?;
        Ok(AuthenticatedActor { actor, bearer })
    }

    pub async fn verify_token(
        &self,
        token: &str,
        required_scope: &str,
    ) -> Result<VerifiedActor, AuthError> {
        if !strict_credential(token) {
            return Err(AuthError::Unauthorized);
        }
        let claims = self
            .client
            .introspect_with_requirements(token, &self.policy.audience, &[required_scope])
            .await
            .map_err(|error| match error {
                shared_auth_client::ClientError::Unauthorized
                | shared_auth_client::ClientError::InvalidInput(_) => AuthError::Unauthorized,
                _ => AuthError::Degraded,
            })?;
        authorize_introspection(&claims, &self.policy, required_scope, unix_seconds()?).map_err(
            |error| match error {
                eal_api_server::auth::AuthError::Unauthorized => AuthError::Unauthorized,
                eal_api_server::auth::AuthError::Degraded => AuthError::Degraded,
                eal_api_server::auth::AuthError::Configuration => AuthError::Configuration,
            },
        )
    }

    pub fn product_tenant(&self) -> &str {
        &self.policy.product_tenant
    }
}

fn request_bearer(headers: &HeaderMap) -> Result<&str, AuthError> {
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    if let Some(value) = authorization.next() {
        if authorization.next().is_some() {
            return Err(AuthError::Unauthorized);
        }
        return value
            .to_str()
            .ok()
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| strict_credential(value))
            .ok_or(AuthError::Unauthorized);
    }

    let mut cookies = headers.get_all(header::COOKIE).iter();
    let cookie = cookies
        .next()
        .ok_or(AuthError::Unauthorized)?
        .to_str()
        .map_err(|_| AuthError::Unauthorized)?;
    if cookies.next().is_some() || cookie.len() > MAX_CREDENTIAL_BYTES * 2 {
        return Err(AuthError::Unauthorized);
    }
    let mut matches = cookie.split(';').filter_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == "eal_access_token").then_some(value)
    });
    let token = matches.next().ok_or(AuthError::Unauthorized)?;
    if matches.next().is_some() || !strict_credential(token) {
        return Err(AuthError::Unauthorized);
    }
    Ok(token)
}

fn strict_credential(value: &str) -> bool {
    value.len() >= 16
        && value.len() <= MAX_CREDENTIAL_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn required_env(name: &str) -> Result<String, AuthError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::Configuration)
}

fn unix_seconds() -> Result<u64, AuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthError::Degraded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use eal_api_server::auth::READ_SCOPE;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Option<(HeaderMap, serde_json::Value)>>>);

    async fn introspect(
        State(capture): State<Capture>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        *capture.0.lock().unwrap() = Some((headers, body));
        Json(serde_json::json!({
            "active": true,
            "sub": "00000000-0000-4000-8000-000000000001",
            "sid": "00000000-0000-4000-8000-000000000002",
            "iss": "https://auth.oresoftware.dev/customer",
            "aud": "embedded-alerts-api",
            "azp": "embedded-alerts-web",
            "scope": READ_SCOPE,
            "nbf": 1,
            "exp": u64::MAX,
            "provider_tenant": "embedded-alerts-provider",
            "tenant_id": "embedded-alerts",
            "application_id": "embedded-alerts-web",
            "actor_kind": "user"
        }))
    }

    #[test]
    fn repeated_authorization_and_cookie_tokens_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            "Bearer a-valid-access-token".parse().unwrap(),
        );
        headers.append(
            header::AUTHORIZATION,
            "Bearer another-access-token".parse().unwrap(),
        );
        assert!(request_bearer(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "eal_access_token=a-valid-access-token; eal_access_token=another-access-token"
                .parse()
                .unwrap(),
        );
        assert!(request_bearer(&headers).is_err());
    }

    #[tokio::test]
    async fn official_client_separates_service_credential_and_user_payload() {
        let capture = Capture::default();
        let app = Router::new()
            .route("/auth/introspect", post(introspect))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let boundary = WebAuthBoundary {
            client: SharedAuthClient::try_new(format!("http://{address}"))
                .unwrap()
                .with_service_credential("independent-service-credential"),
            policy: AuthPolicy {
                issuer: "https://auth.oresoftware.dev/customer".to_owned(),
                audience: "embedded-alerts-api".to_owned(),
                authorized_client: "embedded-alerts-web".to_owned(),
                provider_tenant: "embedded-alerts-provider".to_owned(),
                product_tenant: "embedded-alerts".to_owned(),
            },
        };
        boundary
            .verify_token("end-user-access-token", READ_SCOPE)
            .await
            .unwrap();
        let (headers, body) = capture.0.lock().unwrap().clone().unwrap();
        assert_eq!(
            headers[header::AUTHORIZATION],
            "Bearer independent-service-credential"
        );
        assert_eq!(body["contract"], "IntrospectionRequest");
        assert_eq!(body["payload"]["token"], "end-user-access-token");
        assert_eq!(body["payload"]["audience"], "embedded-alerts-api");
        assert_eq!(body["payload"]["requiredScopes"][0], READ_SCOPE);
        task.abort();
    }
}
