use btc_forum_shared::{ApiError, ErrorCode};

pub fn format_api_error(status: u16, err: ApiError) -> String {
    let base = match err.code {
        ErrorCode::Unauthorized => "未登录或登录失效，请先登录".to_string(),
        ErrorCode::Forbidden => {
            if err.message.contains("csrf") {
                "CSRF 校验失败，请刷新 CSRF 后重试".to_string()
            } else if err.message.contains("banned") {
                "账号已被封禁，无法执行此操作".to_string()
            } else {
                "权限不足，无法执行此操作".to_string()
            }
        }
        ErrorCode::Validation => format!("参数错误：{}", err.message),
        ErrorCode::NotFound => "资源不存在".to_string(),
        ErrorCode::Conflict => format!("操作冲突：{}", err.message),
        ErrorCode::RateLimited => "操作过于频繁，请稍后再试".to_string(),
        ErrorCode::BadGateway => "认证服务不可用，请检查 Rainbow-Auth".to_string(),
        ErrorCode::Internal => "服务内部错误，请稍后再试".to_string(),
    };
    format!("HTTP {status}: {base}")
}
