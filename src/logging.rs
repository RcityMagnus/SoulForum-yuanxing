use crate::security::is_not_banned;
use crate::services::{ForumContext, ForumService, ServiceResult};

pub fn log_action<S: ForumService>(
    service: &S,
    ctx: &mut ForumContext,
    action: &str,
    details: serde_json::Value,
) -> ServiceResult<()> {
    is_not_banned(service, ctx, false)?;
    service.log_action(action, Some(ctx.user_info.id), &details)
}
