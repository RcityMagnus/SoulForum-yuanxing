use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header::HeaderName},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::fs;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use btc_forum_rust::{
    auth::AuthClaims,
    services::{BoardAccessEntry, ForumError},
    rainbow_auth::RainbowAuthClient,
    services::{
        BanAffects, BanCondition, BanRule, ForumContext, ForumService, PersonalMessageFolder,
        SendPersonalMessage, surreal::SurrealService,
    },
    surreal::{SurrealForumService, SurrealPost, SurrealTopic, SurrealUser, connect_from_env},
};
use btc_forum_shared::{
    AuthMeResponse, AuthResponse, AuthUser, Board, BoardsResponse,
    CreateBoardPayload, ErrorCode, LoginRequest, RegisterRequest, RegisterResponse,
};
use tower_http::cors::CorsLayer;

#[path = "../api/mod.rs"]
mod api;

use api::auth::{bearer_from_headers, ensure_user_ctx, require_auth, user_groups};
use api::error::{api_error, api_error_from_status, rainbow_auth_error_response};
use api::guards::{
    ensure_admin, ensure_board_access, ensure_permission, ensure_permission_for_board,
    fetch_topic_board_id, enforce_rate, load_board_access, validate_content, verify_csrf,
};
use api::state::{
    allowed_mime, csrf_enabled, find_csrf_cookie, generate_csrf_token, max_upload_bytes,
    rainbow_auth_base_url, upload_base_url, upload_dir, AppState, RateLimiter,
};

fn validate_config() {
    let has_secret = env::var("JWT_SECRET").is_ok();
    let has_pub = env::var("JWT_PUBLIC_KEY_PEM").is_ok();
    if !has_secret && !has_pub {
        panic!("either JWT_SECRET or JWT_PUBLIC_KEY_PEM must be set for JWT validation");
    }
    if has_pub {
        tracing::warn!("JWT_PUBLIC_KEY_PEM is set; Rainbow-Auth uses HS256, so prefer JWT_SECRET");
    }
    if !csrf_enabled() {
        tracing::warn!("ENFORCE_CSRF=0 (CSRF protection disabled)");
    }
    if env::var("SURREAL_ENDPOINT").ok().map(|v| v.is_empty()).unwrap_or(false) {
        panic!("SURREAL_ENDPOINT cannot be empty");
    }
    if rainbow_auth_base_url().trim().is_empty() {
        panic!("RAINBOW_AUTH_BASE_URL cannot be empty");
    }
}

async fn run_forum_blocking<T>(
    state: &AppState,
    job: impl FnOnce(&SurrealService) -> Result<T, ForumError> + Send + 'static,
) -> Result<T, ForumError>
where
    T: Send + 'static,
{
    let forum_service = state.forum_service.clone();
    tokio::task::spawn_blocking(move || job(&forum_service))
        .await
        .map_err(|e| ForumError::Internal(format!("forum task failed: {e}")))?
}

fn rate_key(claims: &AuthClaims, addr: Option<&std::net::SocketAddr>) -> String {
    if let Some(ip) = addr {
        format!("{}:{}", claims.sub, ip.ip())
    } else {
        claims.sub.clone()
    }
}

async fn csrf_layer(mut req: Request<Body>, next: Next) -> Response {
    let csrf_on = csrf_enabled();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let mut set_cookie: Option<String> = None;

    if csrf_on {
        // Issue a token cookie for safe methods to reduce friction on first load.
        if matches!(method, Method::GET | Method::OPTIONS) && find_csrf_cookie(req.headers()).is_none()
        {
            set_cookie = Some(generate_csrf_token());
        }

        if !matches!(method, Method::GET | Method::OPTIONS) && !path.starts_with("/auth/") {
            let headers = req.headers().clone();
            if let Err(err) = verify_csrf(&headers) {
                return err.into_response();
            }
            req.extensions_mut().insert(headers);
        }
    }

    let mut response = next.run(req).await;
    if let Some(token) = set_cookie {
        if let Ok(value) =
            HeaderValue::from_str(&format!("XSRF-TOKEN={}; Path=/; SameSite=Lax", token))
        {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}

fn sanitize_input(input: &str) -> String {
    ammonia::Builder::default()
        .url_schemes(["http", "https"].into())
        .clean(input)
        .to_string()
}

fn sanitize_filename(name: &str) -> String {
    let base = name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(name);
    let mut cleaned: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();
    if cleaned.is_empty() {
        cleaned = format!("upload-{}.bin", Utc::now().timestamp_millis());
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::Request, middleware::from_fn, routing::post};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    #[test]
    fn validate_content_ok() {
        assert!(api::guards::validate_content("hello", "body").is_ok());
    }

    #[test]
    fn validate_content_empty_subject_err() {
        assert!(api::guards::validate_content("", "body").is_err());
    }

    #[test]
    fn validate_content_empty_body_err() {
        assert!(api::guards::validate_content("hello", " ").is_err());
    }

    #[test]
    fn require_auth_rejects_missing_claims() {
        let result = api::auth::require_auth(&None);
        assert!(result.is_err());
    }

    #[test]
    fn csrf_mismatch_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", HeaderValue::from_static("abc"));
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("XSRF-TOKEN=def"),
        );
        assert!(api::guards::verify_csrf(&headers).is_err());
    }

    #[test]
    fn rate_limiter_hits_limit() {
        let limiter = api::state::RateLimiter::new();
        let key = "user1";
        assert!(limiter.allow(key, 2, Duration::from_secs(60)));
        assert!(limiter.allow(key, 2, Duration::from_secs(60)));
        assert!(!limiter.allow(key, 2, Duration::from_secs(60)));
    }

    #[test]
    fn rate_key_with_ip() {
        let claims = AuthClaims {
            sub: "alice".into(),
            exp: 0,
            iat: 0,
            session_id: None,
            role: None,
            permissions: None,
        };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let key = rate_key(&claims, Some(&addr));
        assert!(key.contains("alice"));
        assert!(key.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn csrf_layer_blocks_missing_token() {
        let app = Router::new()
            .route("/test", post(|| async { StatusCode::OK }))
            .layer(from_fn(csrf_layer));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_layer_allows_with_token() {
        let app = Router::new()
            .route("/test", post(|| async { StatusCode::OK }))
            .layer(from_fn(csrf_layer));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("x-csrf-token", "abc")
            .header(axum::http::header::COOKIE, "XSRF-TOKEN=abc")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    validate_config();
    init_tracing();

    let surreal = connect_from_env()
        .await
        .expect("failed to connect to SurrealDB");
    let surreal = SurrealForumService::new(surreal);
    let forum_service = SurrealService::new(surreal.client().clone());
    let rainbow_auth = RainbowAuthClient::new(rainbow_auth_base_url());
    let cors_origin =
        env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let state = AppState {
        surreal,
        forum_service,
        rainbow_auth,
        rate_limiter: Arc::new(RateLimiter::new()),
        start_time: Instant::now(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/me", get(auth_me))
        .route("/ui", get(ui))
        .route("/demo/post", post(demo_post))
        .route("/demo/surreal", post(demo_surreal))
        .route("/surreal/post", post(surreal_post))
        .route("/surreal/posts", get(surreal_posts))
        .route("/surreal/notifications", get(list_notifications).post(create_notification))
        .route(
            "/surreal/notifications/mark_read",
            post(mark_notification_read),
        )
        .route(
            "/surreal/attachments",
            get(list_attachments).post(create_attachment_meta),
        )
        .route(
            "/surreal/attachments/delete",
            post(delete_attachment_api),
        )
        .route(
            "/surreal/attachments/upload",
            post(upload_attachment),
        )
        .route("/uploads/*path", get(serve_upload))
        .route("/surreal/personal_messages", get(list_personal_messages))
        .route(
            "/surreal/personal_messages/send",
            post(send_personal_message_api),
        )
        .route(
            "/surreal/personal_messages/read",
            post(mark_personal_messages_read),
        )
        .route(
            "/surreal/personal_messages/delete",
            post(delete_personal_messages_api),
        )
        .route(
            "/surreal/boards",
            get(surreal_boards).post(create_surreal_board),
        )
        .route(
            "/surreal/topics",
            get(list_surreal_topics).post(create_surreal_topic),
        )
        .route(
            "/surreal/topic/posts",
            get(list_surreal_posts_for_topic).post(create_surreal_topic_post),
        )
        .route("/admin/users", get(list_users))
        .route("/admin/admins", get(list_admins))
        .route("/admin/groups", get(list_groups))
        .route("/admin/bans", get(list_bans))
        .route("/admin/action_logs", get(list_action_logs))
        .route("/admin/bans/apply", post(apply_ban))
        .route("/admin/bans/revoke", post(revoke_ban))
        .route("/admin/notify", post(admin_notify))
        .route("/admin/board_access", get(get_board_access).post(update_board_access))
        .route(
            "/admin/board_permissions",
            get(get_board_permissions).post(update_board_permissions),
        )
        .layer(axum::middleware::from_fn(csrf_layer))
        .layer({
            let origin = cors_origin
                .parse::<HeaderValue>()
                .expect("invalid CORS_ORIGIN");
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    HeaderName::from_static("x-csrf-token"),
                ])
                .allow_credentials(true)
        })
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()
        .expect("invalid BIND_ADDR, expected host:port");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind HTTP listener");
    info!("API listening on http://{addr}");

    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server crashed");
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let surreal_status = match state.surreal.health().await {
        Ok(_) => json!({"status": "ok"}),
        Err(err) => {
            error!(error = %err, "surreal connectivity check failed");
            json!({"status": "error", "message": err.to_string()})
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "service": "ok (surreal-only)",
            "surreal": surreal_status,
            "timestamp": Utc::now()
        })),
    )
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let rates = state.rate_limiter.snapshot();
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "uptime_secs": uptime,
            "rate_limiter_keys": rates,
        })),
    )
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> Response {
    let key = format!("register:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 5, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let email = payload.email.trim();
    if email.is_empty() || !email.contains('@') {
        return api_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::Validation,
            "valid email required",
        )
        .into_response();
    }
    if payload.password.len() < 6 || payload.password.len() > 128 {
        return api_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::Validation,
            "password must be 6-128 chars",
        )
        .into_response();
    }

    match state
        .rainbow_auth
        .register(email, &payload.password)
        .await
    {
        Ok(message) => (
            StatusCode::OK,
            Json(RegisterResponse {
                status: "ok".to_string(),
                message,
            }),
        )
            .into_response(),
        Err(err) => rainbow_auth_error_response(err).into_response(),
    }
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let key = format!("login:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 10, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let email = payload.email.trim();
    if email.is_empty() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "email required").into_response();
    }

    match state
        .rainbow_auth
        .login(email, &payload.password)
        .await
    {
        Ok(login) => {
            let forum_user = match state
                .surreal
                .ensure_user(&login.user.email, None, None)
                .await
            {
                Ok(user) => user,
                Err(err) => {
                    error!(error = %err, "failed to ensure user after login");
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ErrorCode::Internal,
                        "failed to sync user",
                    )
                    .into_response();
                }
            };
            let member_id = forum_user.legacy_id();
            (
                StatusCode::OK,
                Json(AuthResponse {
                    status: "ok".to_string(),
                    token: login.token,
                    user: AuthUser {
                        name: login.user.email,
                        role: None,
                        permissions: Some(Vec::new()),
                        member_id: Some(member_id),
                    },
                }),
            )
                .into_response()
        }
        Err(err) => rainbow_auth_error_response(err).into_response(),
    }
}

async fn auth_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_from_headers(&headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "authorization required",
        )
        .into_response();
    };

    match state.rainbow_auth.me(&token).await {
        Ok(user) => {
            let member_id = match state
                .surreal
                .ensure_user(&user.email, None, None)
                .await
            {
                Ok(forum_user) => forum_user.legacy_id(),
                Err(err) => {
                    error!(error = %err, "failed to sync user for auth/me");
                    0
                }
            };
            (
                StatusCode::OK,
                Json(AuthMeResponse {
                    status: "ok".to_string(),
                    user: AuthUser {
                        name: user.email,
                        role: None,
                        permissions: Some(Vec::new()),
                        member_id: Some(member_id),
                    },
                }),
            )
                .into_response()
        }
        Err(err) => rainbow_auth_error_response(err).into_response(),
    }
}

/// CSRF 占位：如需 CSRF 防护，可在前端携带 token（双提交或表单隐藏字段），
/// 后端通过中间件校验自定义 Header 与 Cookie 一致性，再放行路由。

async fn ui() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forum Demo</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto; line-height: 1.6; }
    label { display: block; margin-top: 12px; }
    textarea, input { width: 100%; padding: 8px; }
    button { margin-top: 12px; padding: 10px 16px; cursor: pointer; }
    pre { background: #f4f4f4; padding: 12px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>Forum Demo</h1>
  <p>Paste a JWT (from Rainbow-Auth) and post a sample message via the demo endpoint.</p>
  <label>JWT Bearer Token</label>
  <textarea id="token" rows="3" placeholder="eyJhbGciOi..."></textarea>
  <button id="send">Send Demo Post</button>
  <pre id="output">Waiting...</pre>
  <script>
    const btn = document.getElementById('send');
    const out = document.getElementById('output');
    btn.onclick = async () => {
      const token = document.getElementById('token').value.trim();
      if (!token) {
        out.textContent = 'Please provide a JWT token.';
        return;
      }
      out.textContent = 'Sending...';
      try {
        const res = await fetch('/demo/post', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token
          }
        });
        const text = await res.text();
        out.textContent = text;
      } catch (err) {
        out.textContent = 'Error: ' + err;
      }
    };
  </script>
</body>
</html>"#,
    )
}

async fn demo_surreal(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, _) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let author = user.name.clone();
    match state
        .surreal
        .create_demo_post(
            "Surreal demo",
            "Hello from SurrealDB demo endpoint",
            &author,
        )
        .await
    {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "record": record
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "surreal demo failed");
            api_error_from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateSurrealPost {
    board_id: String,
    subject: String,
    body: String,
}

async fn surreal_post(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateSurrealPost>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = validate_content(&payload.subject, &payload.body) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if let Err(resp) = ensure_board_access(&state, &ctx, &payload.board_id).await {
        return resp.into_response();
    }
    if let Err(resp) = ensure_permission_for_board(&state, &ctx, "post_new", Some(&payload.board_id)).await
    {
        return resp.into_response();
    }
    let author = user.name.clone();
    match state
        .surreal
        .create_post(
            &sanitize_input(&payload.subject),
            &sanitize_input(&payload.body),
            &author,
        )
        .await
    {
        Ok(post) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "ok",
                "post": post
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create surreal post");
            api_error_from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            )
                .into_response()
        }
    }
}

async fn surreal_posts(
    State(state): State<AppState>,
    _claims: Option<AuthClaims>,
) -> impl IntoResponse {
    match state.surreal.list_posts().await {
        Ok(posts) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "posts": posts
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list surreal posts");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                err.to_string(),
            )
                .into_response()
        }
    }
}

async fn create_surreal_board(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<CreateBoardPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 10, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if payload.name.trim().is_empty() || payload.name.trim().len() > 100 {
        return api_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::Validation,
            "name must be 1..100 chars",
        )
        .into_response();
    }
    if let Err(resp) = ensure_permission(&state, &ctx, "manage_boards") {
        return resp.into_response();
    }
    match state
        .surreal
        .create_board(&payload.name, payload.description.as_deref())
        .await
    {
        Ok(board) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "board": board})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create board");
            api_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::Validation,
                err.to_string(),
            )
                .into_response()
        }
    }
}

async fn surreal_boards(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let mut ctx = ForumContext::default();
    if let Some(claims) = claims {
        if let Ok((_user, c)) = ensure_user_ctx(&state, &claims).await {
            ctx = c;
        }
    }
    let access_rules: Option<Vec<BoardAccessEntry>> = load_board_access(&state).await.ok();
    match state.surreal.list_boards().await {
        Ok(boards) => {
            let filtered = match access_rules {
                Some(rules) => boards
                    .into_iter()
                    .filter(|b| {
                        if ctx.user_info.is_admin {
                            return true;
                        }
                        if let Some(rule) = rules.iter().find(|r| r.id == b.id.clone().unwrap_or_default()) {
                            if rule.allowed_groups.is_empty() {
                                return true;
                            }
                            let groups = user_groups(&ctx);
                            rule.allowed_groups.iter().any(|gid| groups.iter().any(|g| g == gid))
                        } else {
                            true
                        }
                    })
                    .map(|b| Board {
                        id: b.id,
                        name: b.name,
                        description: b.description,
                        created_at: b.created_at,
                        updated_at: None,
                    })
                    .collect(),
                None => boards
                    .into_iter()
                    .map(|b| Board {
                        id: b.id,
                        name: b.name,
                        description: b.description,
                        created_at: b.created_at,
                        updated_at: None,
                    })
                    .collect(),
            };
            (
                StatusCode::OK,
                Json(BoardsResponse {
                    status: "ok".to_string(),
                    boards: filtered,
                }),
            )
                .into_response()
        }
        Err(err) => {
            error!(error = %err, "failed to list boards");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                err.to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateTopicPayload {
    board_id: String,
    subject: String,
    body: String,
}

async fn create_surreal_topic(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateTopicPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = validate_content(&payload.subject, &payload.body) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if let Err(resp) = ensure_board_access(&state, &ctx, &payload.board_id).await {
        return resp.into_response();
    }
    if let Err(resp) = ensure_permission_for_board(&state, &ctx, "post_new", Some(&payload.board_id)).await
    {
        return resp.into_response();
    }
    let author = user.name.clone();
    let topic_result: Result<(SurrealTopic, SurrealPost), surrealdb::Error> = async {
        let topic = state
            .surreal
            .create_topic(
                &payload.board_id,
                &sanitize_input(&payload.subject),
                &author,
            )
            .await?;
        // create initial post inside the topic
        let topic_id = topic.id.clone().unwrap_or_default();
        let post = state
            .surreal
            .create_post_in_topic(
                &topic_id,
                &payload.board_id,
                &sanitize_input(&payload.subject),
                &sanitize_input(&payload.body),
                &author,
            )
            .await?;
        Ok((topic, post))
    }
    .await;

    match topic_result {
        Ok((topic, post)) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "topic": topic, "first_post": post})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create topic");
            api_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::Validation,
                err.to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct ListTopicsParams {
    board_id: String,
}

async fn list_surreal_topics(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(params): Query<ListTopicsParams>,
) -> impl IntoResponse {
    let mut ctx = ForumContext::default();
    if let Some(claims) = claims {
        if let Ok((_user, c)) = ensure_user_ctx(&state, &claims).await {
            ctx = c;
        }
    }
    if let Err(resp) = ensure_board_access(&state, &ctx, &params.board_id).await {
        return resp.into_response();
    }
    match state.surreal.list_topics(&params.board_id).await {
        Ok(topics) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "topics": topics})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list topics");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                err.to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreatePostPayload {
    topic_id: String,
    board_id: String,
    subject: Option<String>,
    body: String,
}

async fn create_surreal_topic_post(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreatePostPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 40, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let subject = payload
        .subject
        .clone()
        .unwrap_or_else(|| "Re: topic".into());
    if let Err(resp) = validate_content(&subject, &payload.body) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if let Err(resp) = ensure_board_access(&state, &ctx, &payload.board_id).await {
        return resp.into_response();
    }
    // Basic XSS mitigation by sanitizing HTML content
    if let Err(resp) =
        ensure_permission_for_board(&state, &ctx, "post_reply_any", Some(&payload.board_id)).await
    {
        return resp.into_response();
    }
    let author = user.name.clone();
    match state
        .surreal
        .create_post_in_topic(
            &payload.topic_id,
            &payload.board_id,
            &sanitize_input(&subject),
            &sanitize_input(&payload.body),
            &author,
        )
        .await
    {
        Ok(post) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "post": post})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create post");
            api_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::Validation,
                err.to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct ListPostsParams {
    topic_id: String,
}

async fn list_surreal_posts_for_topic(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(params): Query<ListPostsParams>,
) -> impl IntoResponse {
    let mut ctx = ForumContext::default();
    if let Some(claims) = claims {
        if let Ok((_user, c)) = ensure_user_ctx(&state, &claims).await {
            ctx = c;
        }
    }
    if let Some(board_id) = fetch_topic_board_id(state.surreal.client(), &params.topic_id).await {
        if let Err(resp) = ensure_board_access(&state, &ctx, &board_id).await {
            return resp.into_response();
        }
    }
    match state.surreal.list_posts_for_topic(&params.topic_id).await {
        Ok(posts) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "posts": posts})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list posts");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                err.to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateNotificationPayload {
    user: Option<String>,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct MarkNotificationPayload {
    id: String,
}

#[derive(Deserialize)]
struct CreateAttachmentPayload {
    filename: String,
    size_bytes: i64,
    mime_type: Option<String>,
    board_id: Option<String>,
    topic_id: Option<String>,
}

#[derive(Deserialize)]
struct PersonalMessageSendPayload {
    to: Vec<String>,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct PersonalMessageIdsPayload {
    ids: Vec<i64>,
}

#[derive(Deserialize)]
struct PersonalMessageListQuery {
    folder: Option<String>,
    label: Option<i64>,
    offset: Option<usize>,
    limit: Option<usize>,
}

async fn create_notification(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateNotificationPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    let key = format!("notify:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let target_user = if ctx.user_info.is_admin {
        payload.user.unwrap_or_else(|| claims.sub.clone())
    } else {
        claims.sub.clone()
    };
    if payload.subject.trim().is_empty() || payload.subject.len() > 200 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "subject must be 1-200 chars")
            .into_response();
    }
    if payload.body.trim().is_empty() || payload.body.len() > 4000 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "body must be 1-4000 chars")
            .into_response();
    }
    match state
        .surreal
        .create_notification(&target_user, &sanitize_input(&payload.subject), &sanitize_input(&payload.body))
        .await
    {
        Ok(note) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "notification": note})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create notification");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn mark_notification_read(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<MarkNotificationPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.id.trim().is_empty() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "id required")
            .into_response();
    }
    match state
        .surreal
        .mark_notification_read(&payload.id)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "id": payload.id, "user": claims.sub})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to mark notification read");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn list_attachments(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let base_url = upload_base_url();
    match state.surreal.list_attachments_for_user(&claims.sub).await {
        Ok(items) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "attachments": items, "base_url": base_url})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list attachments");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn create_attachment_meta(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateAttachmentPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    let key = format!("attach:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 30, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if payload.filename.trim().is_empty() || payload.filename.len() > 255 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "filename must be 1-255 chars")
            .into_response();
    }
    if payload.size_bytes < 0 || payload.size_bytes > max_upload_bytes() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "size_bytes invalid")
            .into_response();
    }
    if let Some(list) = allowed_mime() {
        if let Some(mt) = payload.mime_type.as_deref() {
            let mt_lower = mt.to_lowercase();
            if !list.iter().any(|allowed| mt_lower.starts_with(allowed)) {
                return api_error_from_status(StatusCode::BAD_REQUEST, "mime_type not allowed")
                    .into_response();
            }
        }
    }
    let base_url = upload_base_url();
    match state
        .surreal
        .create_attachment_meta(
            &claims.sub,
            &payload.filename,
            payload.size_bytes,
            payload.mime_type.as_deref(),
            payload.board_id.as_deref(),
            payload.topic_id.as_deref(),
        )
        .await
    {
        Ok(att) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "attachment": att, "base_url": base_url})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create attachment meta");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn upload_attachment(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    let key = format!("attach_upload:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 10, Duration::from_secs(60)) {
        return resp.into_response();
    }

    let mut file_bytes: Option<Bytes> = None;
    let mut file_name: Option<String> = None;
    let mut mime: Option<String> = None;
    let mut board_id: Option<String> = None;
    let mut topic_id: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(|s| s.to_string());
        match name.as_deref() {
            Some("file") => {
                file_name = field.file_name().map(|s| s.to_string());
                mime = field.content_type().map(|s| s.to_string());
                match field.bytes().await {
                    Ok(bytes) => file_bytes = Some(bytes),
                    Err(err) => {
                        error!(error = %err, "failed to read upload");
                        return api_error_from_status(StatusCode::BAD_REQUEST, "failed to read upload")
                            .into_response();
                    }
                }
            }
            Some("board_id") => {
                if let Ok(text) = field.text().await {
                    board_id = Some(text);
                }
            }
            Some("topic_id") => {
                if let Ok(text) = field.text().await {
                    topic_id = Some(text);
                }
            }
            _ => {}
        }
    }

    let Some(bytes) = file_bytes else {
        return api_error_from_status(StatusCode::BAD_REQUEST, "missing file field")
            .into_response();
    };
    let raw_name = file_name.unwrap_or_else(|| "upload.bin".into());
    let safe_name = sanitize_filename(&raw_name);
    let size_bytes = bytes.len() as i64;
    if size_bytes == 0 || size_bytes > max_upload_bytes() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "file size must be 1..max")
            .into_response();
    }
    if let Some(list) = allowed_mime() {
        if let Some(mt) = mime.clone() {
            let mt_lower = mt.to_lowercase();
            if !list.iter().any(|allowed| mt_lower.starts_with(allowed)) {
                return api_error_from_status(StatusCode::BAD_REQUEST, "mime_type not allowed")
                    .into_response();
            }
        }
    }

    let dir = upload_dir();
    if let Err(err) = fs::create_dir_all(&dir).await {
        error!(error = %err, "failed to create upload dir");
        return api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, "server cannot create upload dir")
            .into_response();
    }

    let mut path = dir.join(&safe_name);
    let (stem, ext) = match path.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => (stem.to_string(), path.extension().and_then(|e| e.to_str()).map(|e| e.to_string())),
        None => (safe_name.clone(), None),
    };
    let mut counter = 1;
    while fs::try_exists(&path).await.unwrap_or(false) {
        let new_name = if let Some(ext) = &ext {
            format!("{stem}-{counter}.{ext}")
        } else {
            format!("{stem}-{counter}")
        };
        path = dir.join(&new_name);
        counter += 1;
    }
    let final_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&safe_name)
        .to_string();

    if let Err(err) = fs::write(&path, &bytes).await {
        error!(error = %err, "failed to write upload");
        return api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, "failed to write upload")
            .into_response();
    }

    let base_url = upload_base_url();
    let public_url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        &final_name
    );

    match state
        .surreal
        .create_attachment_meta(
            &claims.sub,
            &final_name,
            size_bytes,
            mime.as_deref(),
            board_id.as_deref(),
            topic_id.as_deref(),
        )
        .await
    {
        Ok(att) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "attachment": att, "url": public_url, "base_url": base_url})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to store attachment meta");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct DeleteAttachmentPayload {
    id: String,
}

async fn delete_attachment_api(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<DeleteAttachmentPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let id_num = payload
        .id
        .split(':')
        .last()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if id_num <= 0 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "invalid id")
            .into_response();
    }
    // Only owner or admin can delete.
    if !ctx.user_info.is_admin {
        match state.surreal.list_attachments_for_user(&claims.sub).await {
            Ok(items) => {
                if !items.iter().any(|a| a.id.as_deref() == Some(&payload.id)) {
                    return api_error_from_status(StatusCode::FORBIDDEN, "not allowed to delete")
                        .into_response();
                }
            }
            Err(err) => {
                error!(error = %err, "failed to load attachments for delete");
                return api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, "cannot verify ownership")
                    .into_response();
            }
        }
    }
    match run_forum_blocking(&state, move |forum| forum.delete_attachment(id_num)).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "id": payload.id})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, user = %claims.sub, "failed to delete attachment");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn serve_upload(Path(path): axum::extract::Path<String>) -> impl IntoResponse {
    let mut full = upload_dir();
    // basic traversal guard
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            continue;
        }
        full.push(segment);
    }
    match fs::read(&full).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND.into_response()
            } else {
                error!(error = %err, ?full, "failed to read uploaded file");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

async fn list_personal_messages(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(query): Query<PersonalMessageListQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let folder = match query.folder.as_deref().unwrap_or("inbox").to_lowercase().as_str() {
        "sent" => PersonalMessageFolder::Sent,
        _ => PersonalMessageFolder::Inbox,
    };
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    let label = query.label;
    match run_forum_blocking(&state, move |forum| {
        forum.personal_message_page(ctx.user_info.id, folder.clone(), label, offset, limit)
    }).await {
        Ok(page) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "messages": page.messages, "folder": folder, "total": page.total, "unread": page.unread})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list personal messages");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn send_personal_message_api(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<PersonalMessageSendPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.to.is_empty() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "recipient required")
            .into_response();
    }
    if payload.subject.trim().is_empty() || payload.subject.len() > 200 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "subject must be 1-200 chars")
            .into_response();
    }
    if payload.body.trim().is_empty() || payload.body.len() > 4000 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "body must be 1-4000 chars")
            .into_response();
    }
    let (user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };

    // resolve recipient ids by name
    let recipients = payload.to.clone();
    let recipient_ids = match run_forum_blocking(&state, move |forum| {
        let mut ids = Vec::new();
        for name in recipients {
            match forum.find_member_by_name(&name) {
                Ok(Some(member)) => ids.push(member.id),
                _ => return Err(ForumError::Validation(format!("unknown recipient: {name}"))),
            }
        }
        Ok(ids)
    })
    .await {
        Ok(ids) => ids,
        Err(err) => {
            return api_error_from_status(StatusCode::BAD_REQUEST, err.to_string())
                .into_response();
        }
    };

    let message = SendPersonalMessage {
        sender_id: ctx.user_info.id,
        sender_name: user.name.clone(),
        to: recipient_ids,
        bcc: Vec::new(),
        subject: sanitize_input(&payload.subject),
        body: sanitize_input(&payload.body),
    };
    match run_forum_blocking(&state, move |forum| forum.send_personal_message(message)).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "sent_to": result.recipient_ids})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to send personal message");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn mark_personal_messages_read(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<PersonalMessageIdsPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.ids.is_empty() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "ids required")
            .into_response();
    }
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let ids = payload.ids.clone();
    match run_forum_blocking(&state, move |forum| forum.mark_personal_messages(ctx.user_info.id, &ids, true)).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "ids": payload.ids})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to mark personal messages read");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn delete_personal_messages_api(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<PersonalMessageIdsPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.ids.is_empty() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "ids required")
            .into_response();
    }
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let ids = payload.ids.clone();
    match run_forum_blocking(&state, move |forum| {
        forum.delete_personal_messages(ctx.user_info.id, PersonalMessageFolder::Inbox, &ids)
    })
    .await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "ids": payload.ids})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to delete personal messages");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn list_notifications(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let target = claims.sub.clone();
    match state.surreal.list_notifications(&target).await {
        Ok(items) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "notifications": items})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list notifications");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn demo_post(State(state): State<AppState>, claims: Option<AuthClaims>) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = enforce_rate(&state, &claims.sub, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = enforce_rate(&state, &claims.sub, 30, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let author = user.name.clone();
    if let Err(resp) = ensure_permission(&state, &ctx, "post_new") {
        return resp.into_response();
    }

    let submission = btc_forum_rust::services::PostSubmission {
        topic_id: None,
        board_id: 0,
        message_id: None,
        subject: "API example".into(),
        body: "Hello from Axum demo endpoint".into(),
        icon: "xx".into(),
        approved: true,
        send_notifications: false,
    };
    match run_forum_blocking(&state, move |forum| forum.persist_post(&ctx, submission)).await {
        Ok(posted) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "topic_id": posted.topic_id,
                "post_id": posted.message_id,
                "author": author
            })),
        )
            .into_response(),
        Err(err) => api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            .into_response(),
    }
}

async fn list_users(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(params): Query<AdminUsersQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match run_forum_blocking(&state, move |forum| forum.list_members()).await {
        Ok(members) => {
            let filtered: Vec<_> = members
                .into_iter()
                .filter(|m| {
                    if let Some(ref q) = params.q {
                        m.name.to_lowercase().contains(&q.to_lowercase())
                    } else {
                        true
                    }
                })
                .take(params.limit.unwrap_or(200))
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "members": filtered })),
            )
                .into_response()
        }
        Err(err) => {
            error!(error = %err, "failed to list members");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

#[derive(Serialize)]
struct AdminAccount {
    id: i64,
    name: String,
    role: Option<String>,
    permissions: Vec<String>,
}

#[derive(Serialize)]
struct AdminGroupView {
    id: i64,
    name: String,
}

async fn list_admins(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }

    let mut response = match state
        .surreal
        .client()
        .query(
            r#"
            SELECT meta::id(id) as id, name, role, permissions, password_hash, created_at
            FROM users
            WHERE role = 'admin' OR permissions CONTAINS 'manage_boards'
            ORDER BY created_at ASC;
            "#,
        )
        .await
    {
        Ok(resp) => resp,
        Err(err) => {
            error!(error = %err, "failed to list admin users");
            return api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response();
        }
    };

    let admins: Vec<SurrealUser> = match response.take(0) {
        Ok(value) => value,
        Err(err) => {
            error!(error = %err, "failed to parse admin users");
            return api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response();
        }
    };

    let output: Vec<AdminAccount> = admins
        .into_iter()
        .map(|user| AdminAccount {
            id: user.legacy_id(),
            name: user.name,
            role: user.role,
            permissions: user.permissions.unwrap_or_default(),
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "admins": output })),
    )
        .into_response()
}

async fn list_groups(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match run_forum_blocking(&state, move |forum| forum.list_membergroups()).await {
        Ok(groups) => {
            let output: Vec<AdminGroupView> = groups
                .into_iter()
                .map(|g| AdminGroupView {
                    id: g.id,
                    name: g.name,
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "groups": output })),
            )
                .into_response()
        }
        Err(err) => {
            error!(error = %err, "failed to list membergroups");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminNotifyPayload {
    user_ids: Vec<i64>,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct BanPayload {
    #[serde(default)]
    member_id: Option<i64>,
    #[serde(default)]
    ban_id: Option<i64>,
    reason: Option<String>,
    hours: Option<i64>,
}

#[derive(Deserialize)]
struct AdminUsersQuery {
    q: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct AdminPageQuery {
    _limit: Option<usize>,
    _offset: Option<usize>,
}

#[derive(Deserialize)]
struct BoardAccessPayload {
    board_id: String,
    allowed_groups: Vec<i64>,
}

#[derive(Deserialize)]
struct BoardPermissionPayload {
    board_id: String,
    group_id: i64,
    allow: Vec<String>,
    deny: Vec<String>,
}

async fn admin_notify(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<AdminNotifyPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    let key = rate_key(&claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 5, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.user_ids.is_empty() {
        return api_error_from_status(StatusCode::BAD_REQUEST, "user_ids required")
            .into_response();
    }
    if payload.user_ids.len() > 50 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "user_ids too many (max 50)")
            .into_response();
    }
    if let Err(resp) = validate_content(&payload.subject, &payload.body) {
        return resp.into_response();
    }
    let message = SendPersonalMessage {
        sender_id: 0,
        sender_name: "admin".into(),
        to: payload.user_ids.clone(),
        bcc: Vec::new(),
        subject: sanitize_input(&payload.subject),
        body: sanitize_input(&payload.body),
    };
    let subject = payload.subject.clone();
    let user_ids = payload.user_ids.clone();
    match run_forum_blocking(&state, move |forum| forum.send_personal_message(message)).await {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "sent_to": result.recipient_ids })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to send admin notification");
            let log_payload = json!({
                "error": err.to_string(),
                "subject": subject,
                "user_ids": user_ids,
            });
            let _ = run_forum_blocking(&state, move |forum| {
                forum.log_action("admin_notify_error", None, &log_payload)
            })
            .await;
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn list_bans(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(_): Query<AdminPageQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match run_forum_blocking(&state, move |forum| {
        let bans = forum.list_ban_rules()?;
        let members = forum.list_members()?;
        Ok((bans, members))
    })
    .await
    {
        Ok((bans, members)) => {
            let member_map: HashMap<i64, String> = members
                .into_iter()
                .map(|m| (m.id, m.name))
                .collect();
            let mut view = Vec::new();
            for ban in bans {
                let mut member_ids = Vec::new();
                let mut emails = Vec::new();
                let mut ips = Vec::new();
                for cond in &ban.conditions {
                    match &cond.affects {
                        BanAffects::Account { member_id } => member_ids.push(member_id),
                        BanAffects::Email { value } => emails.push(value.clone()),
                        BanAffects::Ip { value } => ips.push(value.clone()),
                    }
                }
                member_ids.sort_unstable();
                member_ids.dedup();
                emails.sort();
                emails.dedup();
                ips.sort();
                ips.dedup();
                let members = member_ids
                    .iter()
                    .map(|id| {
                        json!({
                            "member_id": id,
                            "name": member_map.get(id).cloned().unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<_>>();
                view.push(json!({
                    "id": ban.id,
                    "reason": ban.reason,
                    "expires_at": ban.expires_at.map(|dt| dt.to_rfc3339()),
                    "members": members,
                    "emails": emails,
                    "ips": ips,
                }));
            }
            (StatusCode::OK, Json(json!({"status": "ok", "bans": view}))).into_response()
        }
        Err(err) => {
            error!(error = %err, "failed to list bans");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn apply_ban(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<BanPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    let member_id = payload.member_id.unwrap_or(0);
    if member_id == 0 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "member_id required")
            .into_response();
    }
    let hours = payload.hours.unwrap_or(24).clamp(1, 24 * 365);
    let until = Utc::now()
        .checked_add_signed(chrono::Duration::hours(hours))
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|| Utc::now().timestamp());
    let rule = BanRule {
        id: 0,
        reason: payload.reason.clone(),
        expires_at: Some(chrono::DateTime::from_timestamp(until, 0).unwrap()),
        conditions: vec![BanCondition {
            id: 0,
            reason: payload.reason.clone(),
            affects: BanAffects::Account { member_id },
            expires_at: Some(chrono::DateTime::from_timestamp(until, 0).unwrap()),
        }],
    };
    match run_forum_blocking(&state, move |forum| forum.save_ban_rule(rule)).await {
        Ok(id) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "ban_id": id, "member_id": member_id})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to apply ban");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn revoke_ban(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<BanPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    let ban_id = payload.ban_id.or(payload.member_id).unwrap_or(0);
    if ban_id == 0 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "ban_id required")
            .into_response();
    }
    match run_forum_blocking(&state, move |forum| forum.delete_ban_rule(ban_id)).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "ban_id": ban_id})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to revoke ban");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn list_action_logs(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(_): Query<AdminPageQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match run_forum_blocking(&state, move |forum| forum.list_action_logs()).await {
        Ok(logs) => (StatusCode::OK, Json(json!({"status": "ok", "logs": logs}))).into_response(),
        Err(err) => {
            error!(error = %err, "failed to list action logs");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn get_board_access(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match load_board_access(&state).await {
        Ok(entries) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "entries": entries})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list board access");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn update_board_access(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<BoardAccessPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.allowed_groups.len() > 1000 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "too many groups")
            .into_response();
    }
    let board_id = payload.board_id.clone();
    let allowed_groups = payload.allowed_groups.clone();
    match run_forum_blocking(&state, move |forum| forum.set_board_access(&board_id, &allowed_groups)).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "board_id": payload.board_id, "allowed_groups": payload.allowed_groups})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to update board access");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct BoardPermissionEntry {
    board_id: String,
    group_id: i64,
    allow: Vec<String>,
    deny: Vec<String>,
}

async fn get_board_permissions(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    let mut response = match state
        .surreal
        .client()
        .query(
            r#"
            SELECT board_id, group_id, allow, deny
            FROM board_permissions;
            "#,
        )
        .await
    {
        Ok(resp) => resp,
        Err(err) => {
            error!(error = %err, "failed to list board permissions");
            return api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response();
        }
    };
    let entries: Vec<BoardPermissionEntry> = response.take(0).unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({"status": "ok", "entries": entries})),
    )
        .into_response()
}

async fn update_board_permissions(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    headers: HeaderMap,
    Json(payload): Json<BoardPermissionPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.allow.len() + payload.deny.len() > 500 {
        return api_error_from_status(StatusCode::BAD_REQUEST, "too many permissions")
            .into_response();
    }

    let result = state
        .surreal
        .client()
        .query(
            r#"
            UPSERT type::thing("board_permissions", string::concat("bp:", $board_id, ":", $group_id)) SET
                board_id = $board_id,
                group_id = $group_id,
                allow = $allow,
                deny = $deny;
            "#,
        )
        .bind(("board_id", payload.board_id.clone()))
        .bind(("group_id", payload.group_id))
        .bind(("allow", payload.allow.clone()))
        .bind(("deny", payload.deny.clone()))
        .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "board_id": payload.board_id,
                "group_id": payload.group_id,
                "allow": payload.allow,
                "deny": payload.deny
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to update board permissions");
            api_error_from_status(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                .into_response()
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    }
}
