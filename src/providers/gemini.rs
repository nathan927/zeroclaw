//! Google Gemini provider with support for:
//! - Direct API key (`GEMINI_API_KEY` env var or config)
//! - Multi-account auth via `auth-profiles.json` (round-robin)
//! - Google OAuth device flow login (auto-refresh, quota rotation)
//! - Gemini CLI OAuth tokens (reuse existing ~/.gemini/ authentication)
//! - Google Cloud ADC (`GOOGLE_APPLICATION_CREDENTIALS`)

use crate::providers::google_oauth::{GoogleOAuthClient, OAuthCredential, OAuthTokenStore};
use crate::providers::traits::Provider;
use async_trait::async_trait;
use directories::UserDirs;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

// ══════════════════════════════════════════════════════════════════════════════
// QUOTA TRACKING
// ══════════════════════════════════════════════════════════════════════════════

/// Per-account quota/rate-limit tracker.
#[derive(Debug)]
struct QuotaTracker {
    /// When this account last received a 429 response.
    last_429_at: Option<Instant>,
    /// Cooldown expiry — do not use this account until this time.
    cooldown_until: Option<Instant>,
    /// Total requests routed through this auth.
    request_count: u64,
    /// Consecutive error count (reset on success).
    consecutive_errors: u32,
}

impl QuotaTracker {
    fn new() -> Self {
        Self {
            last_429_at: None,
            cooldown_until: None,
            request_count: 0,
            consecutive_errors: 0,
        }
    }

    /// Whether this account is currently in cooldown.
    fn is_in_cooldown(&self) -> bool {
        self.cooldown_until
            .map_or(false, |until| Instant::now() < until)
    }

    /// Record a 429 rate-limit hit; apply exponential backoff.
    fn record_rate_limit(&mut self, base_secs: u64, max_secs: u64) {
        self.last_429_at = Some(Instant::now());
        self.consecutive_errors += 1;

        // Exponential backoff: base * 2^(errors-1), capped at max
        let backoff_secs = base_secs
            .saturating_mul(1u64 << self.consecutive_errors.min(10).saturating_sub(1))
            .min(max_secs);

        self.cooldown_until = Some(Instant::now() + std::time::Duration::from_secs(backoff_secs));
    }

    /// Record a successful request; reset error counters.
    fn record_success(&mut self) {
        self.consecutive_errors = 0;
        self.cooldown_until = None;
        self.request_count += 1;
    }

    /// Record a non-429 error.
    fn record_error(&mut self) {
        self.consecutive_errors += 1;
        self.request_count += 1;
    }
}

/// Gemini provider supporting multiple authentication methods
/// with quota-aware rotation.
pub struct GeminiProvider {
    auths: Vec<GeminiAuth>,
    auth_source: String,
    rotation: AtomicUsize,
    client: Client,
    /// Per-auth quota trackers (same length and order as `auths`).
    quota_trackers: Mutex<Vec<QuotaTracker>>,
    /// Base cooldown seconds after a 429.
    cooldown_base_secs: u64,
    /// Max cooldown seconds for exponential backoff.
    cooldown_max_secs: u64,
}

/// Resolved credential — the variant determines both the HTTP auth method
/// and the diagnostic label returned by `auth_source()`.
#[derive(Debug)]
enum GeminiAuth {
    /// Explicit API key from config: sent as `?key=` query parameter.
    ExplicitKey(String),
    /// API key from `GEMINI_API_KEY` env var: sent as `?key=`.
    EnvGeminiKey(String),
    /// API key from `GOOGLE_API_KEY` env var: sent as `?key=`.
    EnvGoogleKey(String),
    /// API key loaded from auth-profiles.json.
    ProfileApiKey(String),
    /// OAuth access token loaded from auth-profiles.json.
    ProfileOAuth(String),
    /// OAuth access token from Gemini CLI: sent as `Authorization: Bearer`.
    OAuthToken(String),
    /// Google OAuth credential with auto-refresh (from `zeroclaw google-auth`).
    GoogleOAuth(Mutex<OAuthCredential>),
}

impl GeminiAuth {
    /// Whether this credential is an API key (sent as `?key=` query param).
    fn is_api_key(&self) -> bool {
        matches!(
            self,
            GeminiAuth::ExplicitKey(_)
                | GeminiAuth::EnvGeminiKey(_)
                | GeminiAuth::EnvGoogleKey(_)
                | GeminiAuth::ProfileApiKey(_)
        )
    }

    /// The raw credential string (for non-GoogleOAuth variants).
    fn credential(&self) -> String {
        match self {
            GeminiAuth::ExplicitKey(s)
            | GeminiAuth::EnvGeminiKey(s)
            | GeminiAuth::EnvGoogleKey(s)
            | GeminiAuth::ProfileApiKey(s)
            | GeminiAuth::ProfileOAuth(s)
            | GeminiAuth::OAuthToken(s) => s.clone(),
            GeminiAuth::GoogleOAuth(cred) => cred.lock().unwrap().access_token.clone(),
        }
    }

    /// Descriptive label for this auth source.
    fn label(&self) -> &str {
        match self {
            GeminiAuth::ExplicitKey(_) => "explicit-key",
            GeminiAuth::EnvGeminiKey(_) => "GEMINI_API_KEY",
            GeminiAuth::EnvGoogleKey(_) => "GOOGLE_API_KEY",
            GeminiAuth::ProfileApiKey(_) => "profile-api-key",
            GeminiAuth::ProfileOAuth(_) => "profile-oauth",
            GeminiAuth::OAuthToken(_) => "gemini-cli-oauth",
            GeminiAuth::GoogleOAuth(cred) => {
                let _ = cred; // can't return dynamic string from &str
                "google-oauth"
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// API REQUEST/RESPONSE TYPES
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct GenerateContentRequest {
    contents: Vec<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<Content>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Debug, Serialize)]
struct Content {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    parts: Vec<Part>,
}

#[derive(Debug, Serialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize)]
struct GenerationConfig {
    temperature: f64,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

#[derive(Debug, Deserialize)]
struct GenerateContentResponse {
    candidates: Option<Vec<Candidate>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct Candidate {
    content: CandidateContent,
}

#[derive(Debug, Deserialize)]
struct CandidateContent {
    parts: Vec<ResponsePart>,
}

#[derive(Debug, Deserialize)]
struct ResponsePart {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

// ══════════════════════════════════════════════════════════════════════════════
// GEMINI CLI TOKEN STRUCTURES
// ══════════════════════════════════════════════════════════════════════════════

/// OAuth token stored by Gemini CLI in `~/.gemini/oauth_creds.json`
#[derive(Debug, Deserialize)]
struct GeminiCliOAuthCreds {
    access_token: Option<String>,
    expiry: Option<String>,
}

impl GeminiProvider {
    /// Create a new Gemini provider.
    ///
    /// Authentication priority:
    /// 1. Explicit API key passed in
    /// 2. `GEMINI_API_KEY` environment variable
    /// 3. `GOOGLE_API_KEY` environment variable
    /// 4. Auth-profiles.json
    /// 5. Google OAuth tokens (`zeroclaw google-auth`)
    /// 6. Gemini CLI OAuth tokens (`~/.gemini/oauth_creds.json`)
    pub fn new(api_key: Option<&str>) -> Self {
        let mut auths = Vec::new();
        let mut auth_source = "none".to_string();

        if let Some(key) = api_key.and_then(Self::normalize_non_empty) {
            auths.push(GeminiAuth::ExplicitKey(key));
            auth_source = "config".to_string();
        } else if let Some(key) = Self::load_non_empty_env("GEMINI_API_KEY") {
            auths.push(GeminiAuth::EnvGeminiKey(key));
            auth_source = "GEMINI_API_KEY env var".to_string();
        } else if let Some(key) = Self::load_non_empty_env("GOOGLE_API_KEY") {
            auths.push(GeminiAuth::EnvGoogleKey(key));
            auth_source = "GOOGLE_API_KEY env var".to_string();
        } else {
            let profile_auths = Self::load_auth_profiles();
            if !profile_auths.is_empty() {
                auth_source = format!("auth-profiles.json ({})", profile_auths.len());
                auths = profile_auths;
            }

            // Load Google OAuth tokens (from `zeroclaw google-auth`)
            let oauth_store = OAuthTokenStore::load();
            let oauth_count = oauth_store.credentials.len();
            if oauth_count > 0 {
                for cred in oauth_store.credentials {
                    auths.push(GeminiAuth::GoogleOAuth(Mutex::new(cred)));
                }
                if auths.len() == oauth_count {
                    auth_source = format!("Google OAuth ({})", oauth_count);
                } else {
                    auth_source = format!("{} + Google OAuth ({})", auth_source, oauth_count);
                }
            }

            // Fall back to Gemini CLI token if nothing else found
            if auths.is_empty() {
                if let Some(token) = Self::try_load_gemini_cli_token() {
                    auths.push(GeminiAuth::OAuthToken(token));
                    auth_source = "Gemini CLI OAuth".to_string();
                }
            }
        }

        let tracker_count = auths.len();
        Self {
            auths,
            auth_source,
            rotation: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
            quota_trackers: Mutex::new((0..tracker_count).map(|_| QuotaTracker::new()).collect()),
            cooldown_base_secs: 60,
            cooldown_max_secs: 900,
        }
    }

    fn normalize_non_empty(value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn load_non_empty_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .and_then(|value| Self::normalize_non_empty(&value))
    }

    fn auth_profiles_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Ok(path) = std::env::var("ZEROCLAW_AUTH_PROFILES") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                paths.push(PathBuf::from(trimmed));
            }
        }

        if let Some(home) = UserDirs::new().map(|u| u.home_dir().to_path_buf()) {
            paths.push(home.join(".zeroclaw").join("auth-profiles.json"));
            paths.push(home.join(".openclaw").join("auth-profiles.json"));
        }

        paths
    }

    fn load_auth_profiles() -> Vec<GeminiAuth> {
        let mut auths = Vec::new();

        for path in Self::auth_profiles_paths() {
            if !path.exists() {
                continue;
            }

            if let Ok(raw) = std::fs::read_to_string(&path) {
                auths.extend(Self::parse_auth_profiles_json(&raw));
            }
        }

        auths
    }

    fn parse_auth_profiles_json(raw: &str) -> Vec<GeminiAuth> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            return Vec::new();
        };

        let mut auths = Vec::new();
        for profile in Self::collect_profile_values(&value) {
            if let Some(auth) = Self::extract_profile_auth(profile) {
                auths.push(auth);
            }
        }

        auths
    }

    fn collect_profile_values<'a>(value: &'a serde_json::Value) -> Vec<&'a serde_json::Value> {
        match value {
            serde_json::Value::Array(items) => items.iter().collect(),
            serde_json::Value::Object(map) => {
                let mut collected = Vec::new();
                for key in [
                    "profiles",
                    "accounts",
                    "auth_profiles",
                    "authProfiles",
                    "providers",
                ] {
                    if let Some(value) = map.get(key) {
                        collected.extend(Self::collect_profile_values(value));
                    }
                }

                if collected.is_empty() {
                    if Self::looks_like_profile(value) {
                        collected.push(value);
                    } else {
                        for entry in map.values() {
                            if Self::looks_like_profile(entry) {
                                collected.push(entry);
                            }
                        }
                    }
                }

                collected
            }
            _ => Vec::new(),
        }
    }

    fn extract_profile_auth(profile: &serde_json::Value) -> Option<GeminiAuth> {
        if !Self::provider_is_google(profile) {
            return None;
        }

        let api_key_fields = [
            "api_key",
            "apiKey",
            "key",
            "google_api_key",
            "gemini_api_key",
        ];
        if let Some(key) = Self::find_string_field(profile, &api_key_fields) {
            if let Some(normalized) = Self::normalize_non_empty(&key) {
                return Some(GeminiAuth::ProfileApiKey(normalized));
            }
        }

        let token_fields = [
            "access_token",
            "accessToken",
            "oauth_token",
            "oauthToken",
            "token",
            "bearer_token",
            "id_token",
        ];
        if let Some(token) = Self::find_string_field(profile, &token_fields) {
            if let Some(normalized) = Self::normalize_non_empty(&token) {
                return Some(GeminiAuth::ProfileOAuth(normalized));
            }
        }

        None
    }

    fn provider_is_google(profile: &serde_json::Value) -> bool {
        let keys = ["provider", "type", "kind", "service"];
        for key in keys {
            if let Some(value) = profile.get(key).and_then(serde_json::Value::as_str) {
                let lower = value.to_ascii_lowercase();
                return lower.contains("google") || lower.contains("gemini");
            }
        }
        true
    }

    fn looks_like_profile(profile: &serde_json::Value) -> bool {
        let keys = [
            "api_key",
            "apiKey",
            "key",
            "access_token",
            "accessToken",
            "oauth_token",
            "oauthToken",
            "token",
            "bearer_token",
            "id_token",
        ];
        Self::find_string_field(profile, &keys).is_some()
    }

    fn find_string_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
        match value {
            serde_json::Value::Object(map) => {
                for key in keys {
                    if let Some(val) = map.get(*key).and_then(serde_json::Value::as_str) {
                        return Some(val.to_string());
                    }
                }

                for nested in ["auth", "oauth", "credentials", "token", "tokens", "google"] {
                    if let Some(value) = map.get(nested) {
                        if let Some(found) = Self::find_string_field(value, keys) {
                            return Some(found);
                        }
                    }
                }

                None
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    if let Some(found) = Self::find_string_field(item, keys) {
                        return Some(found);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Try to load OAuth access token from Gemini CLI's cached credentials.

    /// Location: `~/.gemini/oauth_creds.json`
    fn try_load_gemini_cli_token() -> Option<String> {
        let gemini_dir = Self::gemini_cli_dir()?;
        let creds_path = gemini_dir.join("oauth_creds.json");

        if !creds_path.exists() {
            return None;
        }

        let content = std::fs::read_to_string(&creds_path).ok()?;
        let creds: GeminiCliOAuthCreds = serde_json::from_str(&content).ok()?;

        // Check if token is expired (basic check)
        if let Some(ref expiry) = creds.expiry {
            if let Ok(expiry_time) = chrono::DateTime::parse_from_rfc3339(expiry) {
                if expiry_time < chrono::Utc::now() {
                    tracing::warn!("Gemini CLI OAuth token expired — re-run `gemini` to refresh");
                    return None;
                }
            }
        }

        creds
            .access_token
            .and_then(|token| Self::normalize_non_empty(&token))
    }

    /// Get the Gemini CLI config directory (~/.gemini)
    fn gemini_cli_dir() -> Option<PathBuf> {
        UserDirs::new().map(|u| u.home_dir().join(".gemini"))
    }

    /// Check if Gemini CLI is configured and has valid credentials
    pub fn has_cli_credentials() -> bool {
        Self::try_load_gemini_cli_token().is_some()
    }

    /// Check if any Gemini authentication is available
    pub fn has_any_auth() -> bool {
        Self::load_non_empty_env("GEMINI_API_KEY").is_some()
            || Self::load_non_empty_env("GOOGLE_API_KEY").is_some()
            || !Self::load_auth_profiles().is_empty()
            || OAuthTokenStore::load().count() > 0
            || Self::has_cli_credentials()
    }

    /// Get authentication source description for diagnostics.
    /// Uses the stored value — no env var re-reading at call time.
    pub fn auth_source(&self) -> &str {
        if self.auths.is_empty() {
            "none"
        } else {
            self.auth_source.as_str()
        }
    }

    /// Select the best auth index using quota-aware rotation.
    /// Returns indices ordered by preference: non-cooled-down first,
    /// then least-recently-rate-limited.
    fn select_auth_order(&self) -> Vec<usize> {
        let start = self.rotation.fetch_add(1, Ordering::Relaxed);
        let len = self.auths.len();
        let trackers = self.quota_trackers.lock().unwrap();

        let mut available: Vec<usize> = Vec::new();
        let mut cooled_down: Vec<(usize, Option<Instant>)> = Vec::new();

        for offset in 0..len {
            let idx = (start + offset) % len;
            if idx < trackers.len() && trackers[idx].is_in_cooldown() {
                cooled_down.push((idx, trackers[idx].cooldown_until));
            } else {
                available.push(idx);
            }
        }

        // Sort cooled-down by earliest cooldown expiry (soonest available first)
        cooled_down.sort_by(|a, b| a.1.cmp(&b.1));

        available.extend(cooled_down.into_iter().map(|(idx, _)| idx));
        available
    }

    /// Try to auto-refresh a GoogleOAuth token if expired.
    async fn maybe_refresh_oauth(&self, auth: &GeminiAuth) {
        if let GeminiAuth::GoogleOAuth(cred_mutex) = auth {
            let needs_refresh = {
                let cred = cred_mutex.lock().unwrap();
                cred.is_expired()
            };

            if needs_refresh {
                let old_cred = cred_mutex.lock().unwrap().clone();
                let client = GoogleOAuthClient::new(None, None);
                match client.refresh_token(&old_cred).await {
                    Ok(new_cred) => {
                        tracing::info!(
                            email = %new_cred.email,
                            "Refreshed Google OAuth token"
                        );
                        // Persist refreshed token
                        let mut store = OAuthTokenStore::load();
                        store.upsert(new_cred.clone());
                        let _ = store.save();

                        *cred_mutex.lock().unwrap() = new_cred;
                    }
                    Err(e) => {
                        tracing::warn!(
                            email = %old_cred.email,
                            error = %e,
                            "Failed to refresh Google OAuth token"
                        );
                    }
                }
            }
        }
    }

    fn format_model_name(model: &str) -> String {
        if model.starts_with("models/") {
            model.to_string()
        } else {
            format!("models/{model}")
        }
    }

    fn build_generate_content_url(model: &str, auth: &GeminiAuth) -> String {
        let model_name = Self::format_model_name(model);
        let base_url = format!(
            "https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent"
        );

        if auth.is_api_key() {
            format!("{base_url}?key={}", auth.credential())
        } else {
            base_url
        }
    }

    fn build_generate_content_request(
        &self,
        auth: &GeminiAuth,
        url: &str,
        request: &GenerateContentRequest,
    ) -> reqwest::RequestBuilder {
        let req = self.client.post(url).json(request);
        match auth {
            GeminiAuth::OAuthToken(token) | GeminiAuth::ProfileOAuth(token) => {
                req.bearer_auth(token)
            }
            GeminiAuth::GoogleOAuth(cred) => {
                let token = cred.lock().unwrap().access_token.clone();
                req.bearer_auth(token)
            }
            _ => req,
        }
    }
}

#[async_trait]
impl Provider for GeminiProvider {
    async fn chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        model: &str,
        temperature: f64,
    ) -> anyhow::Result<String> {
        if self.auths.is_empty() {
            anyhow::bail!(
                "Gemini API credentials not found. Options:\n\
                 1. Run `zeroclaw google-auth` to login with Google account\n\
                 2. Set GEMINI_API_KEY env var\n\
                 3. Provide auth-profiles.json (multi-account)\n\
                 4. Run `gemini` CLI to authenticate (tokens will be reused)\n\
                 5. Get an API key from https://aistudio.google.com/app/apikey\n\
                 6. Run `zeroclaw onboard` to configure"
            );
        }

        // Build request
        let system_instruction = system_prompt.map(|sys| Content {
            role: None,
            parts: vec![Part {
                text: sys.to_string(),
            }],
        });

        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".to_string()),
                parts: vec![Part {
                    text: message.to_string(),
                }],
            }],
            system_instruction,
            generation_config: GenerationConfig {
                temperature,
                max_output_tokens: 8192,
            },
        };

        // Quota-aware rotation: prefer non-cooled-down accounts
        let auth_order = self.select_auth_order();
        let mut last_error: Option<anyhow::Error> = None;

        for &idx in &auth_order {
            let auth = &self.auths[idx];

            // Auto-refresh expired Google OAuth tokens
            self.maybe_refresh_oauth(auth).await;

            let url = Self::build_generate_content_url(model, auth);

            let response = self
                .build_generate_content_request(auth, &url, &request)
                .send()
                .await?;

            let status = response.status();

            if !status.is_success() {
                let error_text = response.text().await.unwrap_or_default();

                // Track quota: 429 = rate limited
                if status.as_u16() == 429 {
                    if let Ok(mut trackers) = self.quota_trackers.lock() {
                        if idx < trackers.len() {
                            trackers[idx]
                                .record_rate_limit(self.cooldown_base_secs, self.cooldown_max_secs);
                            tracing::warn!(
                                auth_index = idx,
                                auth_type = auth.label(),
                                "Rate limited (429) — rotating to next account"
                            );
                        }
                    }
                } else {
                    if let Ok(mut trackers) = self.quota_trackers.lock() {
                        if idx < trackers.len() {
                            trackers[idx].record_error();
                        }
                    }
                }

                let err = anyhow::anyhow!("Gemini API error ({status}): {error_text}");
                last_error = Some(err);

                if self.auths.len() == 1 {
                    return Err(last_error.unwrap());
                }
                continue;
            }

            // Success — reset quota tracker
            if let Ok(mut trackers) = self.quota_trackers.lock() {
                if idx < trackers.len() {
                    trackers[idx].record_success();
                }
            }

            let result: GenerateContentResponse = response.json().await?;

            // Check for API error in response body
            if let Some(err) = result.error {
                let err = anyhow::anyhow!("Gemini API error: {}", err.message);
                last_error = Some(err);

                if self.auths.len() == 1 {
                    return Err(last_error.unwrap());
                }
                continue;
            }

            if let Some(text) = result
                .candidates
                .and_then(|c| c.into_iter().next())
                .and_then(|c| c.content.parts.into_iter().next())
                .and_then(|p| p.text)
            {
                return Ok(text);
            }

            last_error = Some(anyhow::anyhow!("No response from Gemini"));
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No response from Gemini")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::AUTHORIZATION;

    /// Create a test provider with the given auths.
    fn test_provider(auths: Vec<GeminiAuth>, source: &str) -> GeminiProvider {
        let count = auths.len();
        GeminiProvider {
            auths,
            auth_source: source.to_string(),
            rotation: AtomicUsize::new(0),
            client: Client::new(),
            quota_trackers: Mutex::new((0..count).map(|_| QuotaTracker::new()).collect()),
            cooldown_base_secs: 60,
            cooldown_max_secs: 900,
        }
    }

    #[test]
    fn normalize_non_empty_trims_and_filters() {
        assert_eq!(
            GeminiProvider::normalize_non_empty(" value "),
            Some("value".into())
        );
        assert_eq!(GeminiProvider::normalize_non_empty(""), None);
        assert_eq!(GeminiProvider::normalize_non_empty(" \t\n"), None);
    }

    #[test]
    fn provider_creates_without_key() {
        let provider = GeminiProvider::new(None);
        // May pick up env vars; just verify it doesn't panic
        let _ = provider.auth_source();
    }

    #[test]
    fn provider_creates_with_key() {
        let provider = GeminiProvider::new(Some("test-api-key"));
        match provider.auths.as_slice() {
            [GeminiAuth::ExplicitKey(key)] => assert_eq!(key, "test-api-key"),
            _ => panic!("Expected explicit API key"),
        }
    }

    #[test]
    fn provider_rejects_empty_key() {
        let provider = GeminiProvider::new(Some(""));
        assert!(!provider
            .auths
            .iter()
            .any(|auth| matches!(auth, GeminiAuth::ExplicitKey(_))));
    }

    #[test]
    fn parse_auth_profiles_api_keys() {
        let json = r#"{
            "profiles": [
                {"provider": "google", "api_key": "k1"},
                {"provider": "gemini", "apiKey": "k2"}
            ]
        }"#;
        let auths = GeminiProvider::parse_auth_profiles_json(json);
        assert_eq!(auths.len(), 2);
        assert!(matches!(auths[0], GeminiAuth::ProfileApiKey(ref key) if key == "k1"));
        assert!(matches!(auths[1], GeminiAuth::ProfileApiKey(ref key) if key == "k2"));
    }

    #[test]
    fn parse_auth_profiles_oauth_tokens() {
        let json = r#"[
            {"type": "google", "access_token": "tok1"},
            {"provider": "google", "auth": {"accessToken": "tok2"}}
        ]"#;
        let auths = GeminiProvider::parse_auth_profiles_json(json);
        assert_eq!(auths.len(), 2);
        assert!(matches!(auths[0], GeminiAuth::ProfileOAuth(ref token) if token == "tok1"));
        assert!(matches!(auths[1], GeminiAuth::ProfileOAuth(ref token) if token == "tok2"));
    }

    #[test]
    fn gemini_cli_dir_returns_path() {
        let dir = GeminiProvider::gemini_cli_dir();
        // Should return Some on systems with home dir
        if UserDirs::new().is_some() {
            assert!(dir.is_some());
            assert!(dir.unwrap().ends_with(".gemini"));
        }
    }

    #[test]
    fn auth_source_explicit_key() {
        let provider = test_provider(vec![GeminiAuth::ExplicitKey("key".into())], "config");
        assert_eq!(provider.auth_source(), "config");
    }

    #[test]
    fn auth_source_none_without_credentials() {
        let provider = test_provider(vec![], "none");
        assert_eq!(provider.auth_source(), "none");
    }

    #[test]
    fn auth_source_oauth() {
        let provider = test_provider(
            vec![GeminiAuth::OAuthToken("ya29.mock".into())],
            "Gemini CLI OAuth",
        );
        assert_eq!(provider.auth_source(), "Gemini CLI OAuth");
    }

    #[test]
    fn model_name_formatting() {
        assert_eq!(
            GeminiProvider::format_model_name("gemini-2.0-flash"),
            "models/gemini-2.0-flash"
        );
        assert_eq!(
            GeminiProvider::format_model_name("models/gemini-1.5-pro"),
            "models/gemini-1.5-pro"
        );
    }

    #[test]
    fn api_key_url_includes_key_query_param() {
        let auth = GeminiAuth::ExplicitKey("api-key-123".into());
        let url = GeminiProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        assert!(url.contains(":generateContent?key=api-key-123"));
    }

    #[test]
    fn oauth_url_omits_key_query_param() {
        let auth = GeminiAuth::OAuthToken("ya29.test-token".into());
        let url = GeminiProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        assert!(url.ends_with(":generateContent"));
        assert!(!url.contains("?key="));
    }

    #[test]
    fn oauth_request_uses_bearer_auth_header() {
        let provider = test_provider(
            vec![GeminiAuth::OAuthToken("ya29.mock-token".into())],
            "Gemini CLI OAuth",
        );

        let auth = GeminiAuth::OAuthToken("ya29.mock-token".into());
        let url = GeminiProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        let body = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".into()),
                parts: vec![Part {
                    text: "hello".into(),
                }],
            }],
            system_instruction: None,
            generation_config: GenerationConfig {
                temperature: 0.7,
                max_output_tokens: 8192,
            },
        };

        let request = provider
            .build_generate_content_request(&auth, &url, &body)
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok()),
            Some("Bearer ya29.mock-token")
        );
    }

    #[test]
    fn api_key_request_does_not_set_bearer_header() {
        let provider = test_provider(
            vec![GeminiAuth::ExplicitKey("api-key-123".into())],
            "config",
        );

        let auth = GeminiAuth::ExplicitKey("api-key-123".into());
        let url = GeminiProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        let body = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".into()),
                parts: vec![Part {
                    text: "hello".into(),
                }],
            }],
            system_instruction: None,
            generation_config: GenerationConfig {
                temperature: 0.7,
                max_output_tokens: 8192,
            },
        };

        let request = provider
            .build_generate_content_request(&auth, &url, &body)
            .build()
            .unwrap();

        assert!(request.headers().get(AUTHORIZATION).is_none());
    }

    #[test]
    fn request_serialization() {
        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".to_string()),
                parts: vec![Part {
                    text: "Hello".to_string(),
                }],
            }],
            system_instruction: Some(Content {
                role: None,
                parts: vec![Part {
                    text: "You are helpful".to_string(),
                }],
            }),
            generation_config: GenerationConfig {
                temperature: 0.7,
                max_output_tokens: 8192,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"text\":\"Hello\""));
        assert!(json.contains("\"temperature\":0.7"));
        assert!(json.contains("\"maxOutputTokens\":8192"));
    }

    #[test]
    fn response_deserialization() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello there!"}]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        assert!(response.candidates.is_some());
        let text = response
            .candidates
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .content
            .parts
            .into_iter()
            .next()
            .unwrap()
            .text;
        assert_eq!(text, Some("Hello there!".to_string()));
    }

    #[test]
    fn error_response_deserialization() {
        let json = r#"{
            "error": {
                "message": "Invalid API key"
            }
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().message, "Invalid API key");
    }

    // ── QuotaTracker tests ──────────────────────────────────────

    #[test]
    fn quota_tracker_initial_state() {
        let tracker = QuotaTracker::new();
        assert!(!tracker.is_in_cooldown());
        assert_eq!(tracker.request_count, 0);
        assert_eq!(tracker.consecutive_errors, 0);
        assert!(tracker.last_429_at.is_none());
        assert!(tracker.cooldown_until.is_none());
    }

    #[test]
    fn quota_tracker_record_success() {
        let mut tracker = QuotaTracker::new();
        tracker.record_success();
        assert_eq!(tracker.request_count, 1);
        assert_eq!(tracker.consecutive_errors, 0);
        assert!(!tracker.is_in_cooldown());
    }

    #[test]
    fn quota_tracker_record_rate_limit_sets_cooldown() {
        let mut tracker = QuotaTracker::new();
        tracker.record_rate_limit(60, 900);

        assert!(tracker.is_in_cooldown());
        assert_eq!(tracker.consecutive_errors, 1);
        assert!(tracker.last_429_at.is_some());
        assert!(tracker.cooldown_until.is_some());
    }

    #[test]
    fn quota_tracker_exponential_backoff() {
        let mut tracker = QuotaTracker::new();

        // First hit: 60 * 2^0 = 60s
        tracker.record_rate_limit(60, 900);
        let first_cooldown = tracker.cooldown_until.unwrap();

        // Second hit: 60 * 2^1 = 120s
        tracker.record_rate_limit(60, 900);
        let second_cooldown = tracker.cooldown_until.unwrap();

        assert!(second_cooldown > first_cooldown);
    }

    #[test]
    fn quota_tracker_max_cooldown_cap() {
        let mut tracker = QuotaTracker::new();

        // Hit rate limit many times — should cap at max
        for _ in 0..20 {
            tracker.record_rate_limit(60, 900);
        }

        let cooldown_duration = tracker.cooldown_until.unwrap() - Instant::now();
        // Should not exceed max + small margin
        assert!(cooldown_duration <= std::time::Duration::from_secs(901));
    }

    #[test]
    fn quota_tracker_success_resets_errors() {
        let mut tracker = QuotaTracker::new();
        tracker.record_rate_limit(60, 900);
        assert!(tracker.is_in_cooldown());
        assert_eq!(tracker.consecutive_errors, 1);

        tracker.record_success();
        assert!(!tracker.is_in_cooldown());
        assert_eq!(tracker.consecutive_errors, 0);
    }

    #[test]
    fn quota_tracker_record_error() {
        let mut tracker = QuotaTracker::new();
        tracker.record_error();
        assert_eq!(tracker.consecutive_errors, 1);
        assert_eq!(tracker.request_count, 1);
        assert!(!tracker.is_in_cooldown()); // non-429 errors don't trigger cooldown
    }

    // ── Quota-aware rotation tests ──────────────────────────────

    #[test]
    fn select_auth_order_no_cooldown() {
        let provider = test_provider(
            vec![
                GeminiAuth::ExplicitKey("k1".into()),
                GeminiAuth::ExplicitKey("k2".into()),
                GeminiAuth::ExplicitKey("k3".into()),
            ],
            "test",
        );

        let order = provider.select_auth_order();
        assert_eq!(order.len(), 3);
        // All indices should be present
        assert!(order.contains(&0));
        assert!(order.contains(&1));
        assert!(order.contains(&2));
    }

    #[test]
    fn select_auth_order_skips_cooled_down() {
        let provider = test_provider(
            vec![
                GeminiAuth::ExplicitKey("k1".into()),
                GeminiAuth::ExplicitKey("k2".into()),
                GeminiAuth::ExplicitKey("k3".into()),
            ],
            "test",
        );

        // Put index 0 in cooldown
        {
            let mut trackers = provider.quota_trackers.lock().unwrap();
            trackers[0].record_rate_limit(60, 900);
        }

        let order = provider.select_auth_order();
        assert_eq!(order.len(), 3);
        // Index 0 should be last (it's in cooldown)
        assert_ne!(order[0], 0);
        assert_eq!(*order.last().unwrap(), 0);
    }

    #[test]
    fn gemini_auth_label_variants() {
        assert_eq!(GeminiAuth::ExplicitKey("k".into()).label(), "explicit-key");
        assert_eq!(
            GeminiAuth::EnvGeminiKey("k".into()).label(),
            "GEMINI_API_KEY"
        );
        assert_eq!(
            GeminiAuth::EnvGoogleKey("k".into()).label(),
            "GOOGLE_API_KEY"
        );
        assert_eq!(
            GeminiAuth::ProfileApiKey("k".into()).label(),
            "profile-api-key"
        );
        assert_eq!(
            GeminiAuth::ProfileOAuth("t".into()).label(),
            "profile-oauth"
        );
        assert_eq!(
            GeminiAuth::OAuthToken("t".into()).label(),
            "gemini-cli-oauth"
        );
    }

    #[test]
    fn gemini_auth_credential_returns_value() {
        assert_eq!(GeminiAuth::ExplicitKey("abc".into()).credential(), "abc");
        assert_eq!(
            GeminiAuth::OAuthToken("ya29.tok".into()).credential(),
            "ya29.tok"
        );
    }

    #[test]
    fn provider_has_quota_trackers_matching_auths() {
        let provider = GeminiProvider::new(Some("test-key"));
        let trackers = provider.quota_trackers.lock().unwrap();
        assert_eq!(trackers.len(), provider.auths.len());
    }
}
