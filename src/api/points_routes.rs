use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use btc_forum_rust::{auth::AuthClaims, points};
use btc_forum_shared::{
    CreatePointsEventPayload, ErrorCode, PointsBalanceResponse, PointsEventCreateResponse,
    PointsLeaderboardResponse,
};

use super::{
    auth::{ensure_user_ctx, require_auth},
    error::api_error,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct LeaderboardParams {
    pub(crate) metric: Option<String>,
    pub(crate) limit: Option<usize>,
}

pub(crate) async fn my_points(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let member_id = ctx.user_info.id;
    match load_balance_with_events(&state, member_id).await {
        Ok((balance, recent_events)) => (
            StatusCode::OK,
            Json(PointsBalanceResponse {
                status: "ok".into(),
                balance,
                recent_events,
            }),
        )
            .into_response(),
        Err(err) => {
            api_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, err).into_response()
        }
    }
}

pub(crate) async fn user_points(
    State(state): State<AppState>,
    Path(member_id): Path<i64>,
) -> impl IntoResponse {
    match load_balance_with_events(&state, member_id).await {
        Ok((balance, recent_events)) => (
            StatusCode::OK,
            Json(PointsBalanceResponse {
                status: "ok".into(),
                balance,
                recent_events,
            }),
        )
            .into_response(),
        Err(err) => {
            api_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, err).into_response()
        }
    }
}

pub(crate) async fn points_leaderboard(
    State(state): State<AppState>,
    Query(params): Query<LeaderboardParams>,
) -> impl IntoResponse {
    let metric = points::parse_metric(params.metric.as_deref());
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    match points::leaderboard(state.surreal.client(), metric.clone(), limit).await {
        Ok(leaderboard) => (
            StatusCode::OK,
            Json(PointsLeaderboardResponse {
                status: "ok".into(),
                metric,
                leaderboard,
            }),
        )
            .into_response(),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            err.to_string(),
        )
        .into_response(),
    }
}

pub(crate) async fn create_points_event_api(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Json(payload): Json<CreatePointsEventPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if !(ctx.user_info.is_admin || ctx.user_info.permissions.contains("manage_boards")) {
        return api_error(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "points event write requires admin-level permission",
        )
        .into_response();
    }
    match points::create_points_event(state.surreal.client(), payload).await {
        Ok((event, balance)) => (
            StatusCode::CREATED,
            Json(PointsEventCreateResponse {
                status: "ok".into(),
                event,
                balance,
            }),
        )
            .into_response(),
        Err(btc_forum_rust::services::ForumError::Validation(message)) => {
            api_error(StatusCode::BAD_REQUEST, ErrorCode::Validation, message).into_response()
        }
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            err.to_string(),
        )
        .into_response(),
    }
}

async fn load_balance_with_events(
    state: &AppState,
    member_id: i64,
) -> Result<
    (
        btc_forum_shared::PointsBalance,
        Vec<btc_forum_shared::PointsEvent>,
    ),
    String,
> {
    let balance = points::get_points_balance(state.surreal.client(), member_id)
        .await
        .map_err(|e| e.to_string())?;
    let recent_events = points::list_recent_points_events(state.surreal.client(), member_id, 20)
        .await
        .map_err(|e| e.to_string())?;
    Ok((balance, recent_events))
}
