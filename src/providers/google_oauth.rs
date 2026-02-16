//! Google OAuth 2.0 Device Authorization Grant (RFC 8628) for Gemini API.
//!
//! Implements the device code flow to authenticate users with their Google account,
//! providing free-tier Gemini API access without requiring manual API key management.
//! Supports automatic token refresh and multi-account credential persistence.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use directories::UserDirs;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ══════════════════════════════════════════════════════════════════════════════
// GOOGLE OAUTH CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════

/// Google's public OAuth client ID used by Gemini CLI.
/// This is a public client — no secret required for device flow.
const DEFAULT_CLIENT_ID: &str =
    "77185425430-4c40gm81t6dpiqo635loaoeppu7m8k3e.apps.googleusercontent.com";

/// Client secret for the public Gemini CLI client.
const DEFAULT_CLIENT_SECRET: &str = "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";

/// OAuth 2.0 device authorization endpoint.
const DEVICE_AUTH_URL: &str = "https://oauth2.googleapis.com/device/code";

/// OAuth 2.0 token endpoint.
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Google userinfo endpoint for fetching account email.
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

/// Scope for Gemini generative language API access.
const GEMINI_SCOPE: &str = "https://www.googleapis.com/auth/generative-language openid email";

/// Default token file name.
const TOKEN_FILE: &str = "google-oauth-tokens.json";

// ══════════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ══════════════════════════════════════════════════════════════════════════════

/// Stored OAuth credential for a single Google account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredential {
    /// Google account email (for display/identification).
    pub email: String,
    /// OAuth access token (short-lived, ~1 hour).
    pub access_token: String,
    /// OAuth refresh token (long-lived, used to obtain new access tokens).
    pub refresh_token: String,
    /// When the access token expires.
    pub expires_at: DateTime<Utc>,
    /// When this credential was first created.
    pub created_at: DateTime<Utc>,
    /// When the access token was last refreshed.
    pub last_refreshed_at: DateTime<Utc>,
}

impl OAuthCredential {
    /// Check if the access token is expired or about to expire (within 5 minutes).
    pub fn is_expired(&self) -> bool {
        Utc::now() + Duration::minutes(5) >= self.expires_at
    }
}

/// Response from Google's device authorization endpoint.
#[derive(Debug, Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_url: String,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}

/// Response from Google's token endpoint.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: Option<String>,
}

/// Error response from Google's token endpoint during polling.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
}

/// Google userinfo response.
#[derive(Debug, Deserialize)]
struct UserInfoResponse {
    email: String,
}

/// Persistent store for multiple Google OAuth credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenStore {
    pub credentials: Vec<OAuthCredential>,
}

impl Default for OAuthTokenStore {
    fn default() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// OAUTH CLIENT
// ══════════════════════════════════════════════════════════════════════════════

/// Google OAuth 2.0 Device Flow client.
pub struct GoogleOAuthClient {
    client_id: String,
    client_secret: String,
    http: Client,
}

impl GoogleOAuthClient {
    /// Create a new OAuth client with optional custom client ID/secret.
    pub fn new(client_id: Option<&str>, client_secret: Option<&str>) -> Self {
        Self {
            client_id: client_id.unwrap_or(DEFAULT_CLIENT_ID).to_string(),
            client_secret: client_secret.unwrap_or(DEFAULT_CLIENT_SECRET).to_string(),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Run the full device authorization flow.
    ///
    /// 1. Request device code from Google
    /// 2. Display user code and verification URL
    /// 3. Poll for authorization until user completes login
    /// 4. Fetch user email for identification
    /// 5. Return complete `OAuthCredential`
    pub async fn device_auth_flow(&self) -> Result<OAuthCredential> {
        // Step 1: Request device code
        let device_resp = self.request_device_code().await?;

        // Step 2: Display instructions to user
        println!();
        println!("🔐 Google OAuth 登入");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  請在瀏覽器中開啟以下網址：");
        println!("  👉 {}", device_resp.verification_url);
        println!();
        println!("  然後輸入以下驗證碼：");
        println!("  🔑 {}", device_resp.user_code);
        println!();
        println!("  等待授權中... ({}秒後逾時)", device_resp.expires_in);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // Step 3: Poll for token
        let token_resp = self
            .poll_for_token(
                &device_resp.device_code,
                device_resp.interval,
                device_resp.expires_in,
            )
            .await?;

        let now = Utc::now();
        let expires_at = now + Duration::seconds(token_resp.expires_in as i64);

        let refresh_token = token_resp
            .refresh_token
            .context("Google did not return a refresh token")?;

        // Step 4: Fetch user email
        let email = self
            .fetch_user_email(&token_resp.access_token)
            .await
            .unwrap_or_else(|_| "unknown@gmail.com".to_string());

        println!();
        println!("✅ 授權成功！帳戶：{email}");

        Ok(OAuthCredential {
            email,
            access_token: token_resp.access_token,
            refresh_token,
            expires_at,
            created_at: now,
            last_refreshed_at: now,
        })
    }

    /// Request a device code from Google's authorization server.
    async fn request_device_code(&self) -> Result<DeviceAuthResponse> {
        let resp = self
            .http
            .post(DEVICE_AUTH_URL)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", GEMINI_SCOPE),
            ])
            .send()
            .await
            .context("Failed to request device code from Google")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Device code request failed ({status}): {body}");
        }

        resp.json::<DeviceAuthResponse>()
            .await
            .context("Failed to parse device code response")
    }

    /// Poll Google's token endpoint until the user completes authorization.
    async fn poll_for_token(
        &self,
        device_code: &str,
        interval: u64,
        expires_in: u64,
    ) -> Result<TokenResponse> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(expires_in);
        let mut poll_interval = std::time::Duration::from_secs(interval);

        loop {
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("Device authorization timed out — user did not complete login");
            }

            tokio::time::sleep(poll_interval).await;

            let resp = self
                .http
                .post(TOKEN_URL)
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("client_secret", self.client_secret.as_str()),
                    ("device_code", device_code),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ])
                .send()
                .await
                .context("Failed to poll token endpoint")?;

            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status.is_success() {
                return serde_json::from_str::<TokenResponse>(&body)
                    .context("Failed to parse token response");
            }

            // Check if it's a pending/slow_down response
            if let Ok(err) = serde_json::from_str::<TokenErrorResponse>(&body) {
                match err.error.as_str() {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        poll_interval += std::time::Duration::from_secs(5);
                        continue;
                    }
                    "access_denied" => {
                        anyhow::bail!("User denied the authorization request");
                    }
                    "expired_token" => {
                        anyhow::bail!("Device code expired — please try again");
                    }
                    other => {
                        anyhow::bail!("Token polling error: {other}");
                    }
                }
            }

            anyhow::bail!("Unexpected token endpoint response ({status}): {body}");
        }
    }

    /// Fetch the authenticated user's email address.
    async fn fetch_user_email(&self, access_token: &str) -> Result<String> {
        let resp = self
            .http
            .get(USERINFO_URL)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to fetch user info")?;

        if !resp.status().is_success() {
            anyhow::bail!("User info request failed: {}", resp.status());
        }

        let info: UserInfoResponse = resp
            .json()
            .await
            .context("Failed to parse user info response")?;

        Ok(info.email)
    }

    /// Refresh an expired access token using the refresh token.
    pub async fn refresh_token(&self, credential: &OAuthCredential) -> Result<OAuthCredential> {
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", credential.refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .context("Failed to refresh access token")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Token refresh failed ({status}): {body}");
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("Failed to parse refresh token response")?;

        let now = Utc::now();
        Ok(OAuthCredential {
            email: credential.email.clone(),
            access_token: token_resp.access_token,
            refresh_token: token_resp
                .refresh_token
                .unwrap_or_else(|| credential.refresh_token.clone()),
            expires_at: now + Duration::seconds(token_resp.expires_in as i64),
            created_at: credential.created_at,
            last_refreshed_at: now,
        })
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// TOKEN STORE PERSISTENCE
// ══════════════════════════════════════════════════════════════════════════════

impl OAuthTokenStore {
    /// Default file path: `~/.zeroclaw/google-oauth-tokens.json`
    pub fn default_path() -> Option<PathBuf> {
        UserDirs::new().map(|u| u.home_dir().join(".zeroclaw").join(TOKEN_FILE))
    }

    /// Load token store from disk.
    pub fn load() -> Self {
        Self::default_path()
            .and_then(|path| {
                if path.exists() {
                    std::fs::read_to_string(&path).ok()
                } else {
                    None
                }
            })
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default()
    }

    /// Save token store to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::default_path().context("Cannot determine home directory")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let json = serde_json::to_string_pretty(self).context("Failed to serialize token store")?;

        std::fs::write(&path, json).context("Failed to write token store")?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Add or update a credential (identified by email).
    pub fn upsert(&mut self, credential: OAuthCredential) {
        if let Some(existing) = self
            .credentials
            .iter_mut()
            .find(|c| c.email == credential.email)
        {
            *existing = credential;
        } else {
            self.credentials.push(credential);
        }
    }

    /// Remove a credential by email.
    pub fn remove(&mut self, email: &str) -> bool {
        let len_before = self.credentials.len();
        self.credentials.retain(|c| c.email != email);
        self.credentials.len() < len_before
    }

    /// Get all valid (non-expired or refreshable) credentials.
    pub fn active_credentials(&self) -> &[OAuthCredential] {
        &self.credentials
    }

    /// Get the number of stored credentials.
    pub fn count(&self) -> usize {
        self.credentials.len()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// CLI COMMAND HANDLER
// ══════════════════════════════════════════════════════════════════════════════

/// Handle `zeroclaw google-auth` subcommands.
pub async fn handle_google_auth(
    list: bool,
    remove: Option<String>,
    status: bool,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> Result<()> {
    if list {
        return list_accounts();
    }

    if let Some(email) = remove {
        return remove_account(&email);
    }

    if status {
        return show_status();
    }

    // Default: start device flow login
    let client = GoogleOAuthClient::new(client_id, client_secret);
    let credential = client.device_auth_flow().await?;

    let mut store = OAuthTokenStore::load();
    store.upsert(credential);
    store.save()?;

    println!();
    println!(
        "🎉 已儲存！目前共有 {} 個 Google 帳戶已授權。",
        store.count()
    );

    Ok(())
}

fn list_accounts() -> Result<()> {
    let store = OAuthTokenStore::load();

    if store.credentials.is_empty() {
        println!("尚未登入任何 Google 帳戶。");
        println!("使用 `zeroclaw google-auth` 開始登入。");
        return Ok(());
    }

    println!("🔑 已登入的 Google 帳戶：");
    println!();

    for (i, cred) in store.credentials.iter().enumerate() {
        let status = if cred.is_expired() {
            "⚠️  已過期 (將在使用時自動刷新)"
        } else {
            "✅ 有效"
        };
        println!(
            "  {}. {} — {} (到期: {})",
            i + 1,
            cred.email,
            status,
            cred.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    Ok(())
}

fn remove_account(email: &str) -> Result<()> {
    let mut store = OAuthTokenStore::load();

    if store.remove(email) {
        store.save()?;
        println!("✅ 已移除帳戶：{email}");
    } else {
        println!("❌ 找不到帳戶：{email}");
        println!("使用 `zeroclaw google-auth --list` 查看已登入的帳戶。");
    }

    Ok(())
}

fn show_status() -> Result<()> {
    let store = OAuthTokenStore::load();

    if store.credentials.is_empty() {
        println!("尚未登入任何 Google 帳戶。");
        return Ok(());
    }

    println!("📊 Google OAuth 狀態：");
    println!();

    for cred in &store.credentials {
        let expired = cred.is_expired();
        println!("  帳戶:      {}", cred.email);
        println!(
            "  Token 狀態: {}",
            if expired {
                "⚠️  已過期"
            } else {
                "✅ 有效"
            }
        );
        println!(
            "  到期時間:   {}",
            cred.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  上次刷新:   {}",
            cred.last_refreshed_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  建立時間:   {}",
            cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!();
    }

    println!("共 {} 個帳戶，用於 Gemini API 配額輪換。", store.count());

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_serialization_roundtrip() {
        let cred = OAuthCredential {
            email: "test@gmail.com".to_string(),
            access_token: "ya29.test-token".to_string(),
            refresh_token: "1//test-refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        };

        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: OAuthCredential = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.email, "test@gmail.com");
        assert_eq!(deserialized.access_token, "ya29.test-token");
        assert_eq!(deserialized.refresh_token, "1//test-refresh");
    }

    #[test]
    fn credential_expired_detection() {
        let mut cred = OAuthCredential {
            email: "test@gmail.com".to_string(),
            access_token: "ya29.test".to_string(),
            refresh_token: "1//test".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        };

        assert!(!cred.is_expired(), "Token should not be expired");

        // Set expiry to past
        cred.expires_at = Utc::now() - Duration::minutes(1);
        assert!(cred.is_expired(), "Token should be expired");

        // Set expiry to within 5 minutes (should count as expired)
        cred.expires_at = Utc::now() + Duration::minutes(3);
        assert!(
            cred.is_expired(),
            "Token expiring in 3 min should count as expired"
        );
    }

    #[test]
    fn token_store_default_is_empty() {
        let store = OAuthTokenStore::default();
        assert!(store.credentials.is_empty());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn token_store_upsert_new() {
        let mut store = OAuthTokenStore::default();
        let cred = OAuthCredential {
            email: "user1@gmail.com".to_string(),
            access_token: "tok1".to_string(),
            refresh_token: "ref1".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        };

        store.upsert(cred);

        assert_eq!(store.count(), 1);
        assert_eq!(store.credentials[0].email, "user1@gmail.com");
    }

    #[test]
    fn token_store_upsert_existing_replaces() {
        let mut store = OAuthTokenStore::default();

        store.upsert(OAuthCredential {
            email: "user1@gmail.com".to_string(),
            access_token: "old-token".to_string(),
            refresh_token: "ref1".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        store.upsert(OAuthCredential {
            email: "user1@gmail.com".to_string(),
            access_token: "new-token".to_string(),
            refresh_token: "ref1".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        assert_eq!(store.count(), 1);
        assert_eq!(store.credentials[0].access_token, "new-token");
    }

    #[test]
    fn token_store_remove() {
        let mut store = OAuthTokenStore::default();

        store.upsert(OAuthCredential {
            email: "user1@gmail.com".to_string(),
            access_token: "tok1".to_string(),
            refresh_token: "ref1".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        store.upsert(OAuthCredential {
            email: "user2@gmail.com".to_string(),
            access_token: "tok2".to_string(),
            refresh_token: "ref2".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        assert!(store.remove("user1@gmail.com"));
        assert_eq!(store.count(), 1);
        assert_eq!(store.credentials[0].email, "user2@gmail.com");

        assert!(!store.remove("nonexistent@gmail.com"));
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn token_store_serialization_roundtrip() {
        let mut store = OAuthTokenStore::default();

        store.upsert(OAuthCredential {
            email: "user1@gmail.com".to_string(),
            access_token: "tok1".to_string(),
            refresh_token: "ref1".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        store.upsert(OAuthCredential {
            email: "user2@gmail.com".to_string(),
            access_token: "tok2".to_string(),
            refresh_token: "ref2".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        let json = serde_json::to_string(&store).unwrap();
        let deserialized: OAuthTokenStore = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.count(), 2);
        assert_eq!(deserialized.credentials[0].email, "user1@gmail.com");
        assert_eq!(deserialized.credentials[1].email, "user2@gmail.com");
    }

    #[test]
    fn token_store_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-tokens.json");

        let mut store = OAuthTokenStore::default();
        store.upsert(OAuthCredential {
            email: "persist@gmail.com".to_string(),
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            last_refreshed_at: Utc::now(),
        });

        // Write
        let json = serde_json::to_string_pretty(&store).unwrap();
        std::fs::write(&path, &json).unwrap();

        // Read back
        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: OAuthTokenStore = serde_json::from_str(&content).unwrap();

        assert_eq!(loaded.count(), 1);
        assert_eq!(loaded.credentials[0].email, "persist@gmail.com");
    }

    #[test]
    fn default_path_returns_some() {
        // Should return Some on systems with a home directory
        if UserDirs::new().is_some() {
            let path = OAuthTokenStore::default_path();
            assert!(path.is_some());
            let p = path.unwrap();
            assert!(p.to_string_lossy().contains("google-oauth-tokens.json"));
        }
    }

    #[test]
    fn oauth_client_uses_defaults() {
        let client = GoogleOAuthClient::new(None, None);
        assert_eq!(client.client_id, DEFAULT_CLIENT_ID);
        assert_eq!(client.client_secret, DEFAULT_CLIENT_SECRET);
    }

    #[test]
    fn oauth_client_custom_ids() {
        let client = GoogleOAuthClient::new(Some("custom-id"), Some("custom-secret"));
        assert_eq!(client.client_id, "custom-id");
        assert_eq!(client.client_secret, "custom-secret");
    }

    #[test]
    fn device_auth_response_parsing() {
        let json = r#"{
            "device_code": "4/4-GMMhmH...",
            "user_code": "WDJB-SJHR",
            "verification_url": "https://www.google.com/device",
            "expires_in": 1800,
            "interval": 5
        }"#;

        let resp: DeviceAuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.user_code, "WDJB-SJHR");
        assert_eq!(resp.interval, 5);
        assert_eq!(resp.expires_in, 1800);
    }

    #[test]
    fn token_response_parsing() {
        let json = r#"{
            "access_token": "ya29.a0test...",
            "refresh_token": "1//0test...",
            "expires_in": 3599,
            "token_type": "Bearer"
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "ya29.a0test...");
        assert_eq!(resp.refresh_token, Some("1//0test...".to_string()));
        assert_eq!(resp.expires_in, 3599);
    }

    #[test]
    fn token_error_response_parsing() {
        let json = r#"{"error": "authorization_pending"}"#;
        let resp: TokenErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "authorization_pending");
    }
}
