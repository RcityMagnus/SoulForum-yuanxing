use crate::manage_bans::BanController;
use crate::services::{ForumContext, ForumError, ForumService, ServiceResult};
use serde_json::json;

pub fn admin_main<S: ForumService + Clone>(
    service: &S,
    ctx: &mut ForumContext,
) -> ServiceResult<()> {
    ctx.context.set(
        "admin_menu",
        json!({
            "sections": [
                {"id": "forum", "title": "Forum", "areas": ["index", "news", "packages"]},
                {"id": "config", "title": "Configuration", "areas": ["features", "languages"]},
                {"id": "moderation", "title": "Moderation", "areas": ["bans", "reports"]}
            ]
        }),
    );
    let controller = BanController::new(service.clone());
    controller.list_bans(ctx)?;
    Ok(())
}

pub fn moderation_main<S: ForumService>(_service: &S, ctx: &mut ForumContext) -> ServiceResult<()> {
    ensure_can_moderate(ctx)?;
    ctx.context.set(
        "moderation_menu",
        json!({
            "areas": ["home", "reports", "warnings", "bans"]
        }),
    );
    Ok(())
}

fn ensure_can_moderate(ctx: &ForumContext) -> ServiceResult<()> {
    if ctx.user_info.permissions.contains("moderate_forum") {
        Ok(())
    } else {
        Err(ForumError::PermissionDenied("access_mod_center".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn admin_menu_populates() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        admin_main(&service, &mut ctx).unwrap();
        assert!(ctx.context.get("admin_menu").is_some());
    }

    #[test]
    fn moderation_requires_permission() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        let result = moderation_main(&service, &mut ctx);
        assert!(result.is_err());
    }
}
