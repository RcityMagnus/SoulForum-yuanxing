use crate::personal_messages::pm_link;
use crate::services::{ForumContext, ForumService, ServiceResult};
use serde_json::json;

pub fn manage_news<S: ForumService>(service: &S, ctx: &mut ForumContext) -> ServiceResult<()> {
    let members = service.list_members()?;
    let options: Vec<_> = members
        .iter()
        .map(|member| {
            json!({
                "id": member.id,
                "name": member.name,
                "send_pm": pm_link(ctx, member.id),
            })
        })
        .collect();
    ctx.context.set("newsletter_targets", options);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn manage_news_has_pm_links() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.permissions.insert("pm_send".into());
        ctx.scripturl = "https://forum.local".into();
        manage_news(&service, &mut ctx).unwrap();
        assert!(ctx.context.get("newsletter_targets").is_some());
    }
}
