use crate::services::{ForumContext, ForumError, ForumService, ServiceResult};
use serde_json::json;

pub struct ModerationDashboard<S: ForumService> {
    _service: S,
}

impl<S: ForumService> ModerationDashboard<S> {
    pub fn new(service: S) -> Self {
        Self { _service: service }
    }

    pub fn overview(&self, ctx: &mut ForumContext) -> ServiceResult<()> {
        if !ctx.user_info.permissions.contains("moderate_forum") {
            return Err(ForumError::PermissionDenied("access_mod_center".into()));
        }
        ctx.context.set(
            "moderation_dashboard",
            json!({
                "reports": ctx.mod_settings.int("open_reports").unwrap_or(0),
                "warnings": ctx.mod_settings.int("open_warnings").unwrap_or(0),
            }),
        );
        Ok(())
    }
}
