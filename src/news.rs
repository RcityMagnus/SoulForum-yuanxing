use crate::personal_messages::pm_link;
use crate::services::{ForumContext, ForumService, ServiceResult};
use serde_json::json;

pub fn latest_news<S: ForumService>(service: &S, ctx: &mut ForumContext) -> ServiceResult<()> {
    let members = service.list_members()?;
    let authors: Vec<_> = members
        .iter()
        .take(5)
        .map(|member| {
            json!({
                "author": member.name,
                "send_pm": pm_link(ctx, member.id),
            })
        })
        .collect();
    ctx.context.set("news_authors", authors);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn news_links_to_pm() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.is_guest = false;
        ctx.user_info.permissions.insert("pm_send".into());
        ctx.scripturl = "https://forum.local".into();
        latest_news(&service, &mut ctx).unwrap();
        assert!(ctx.context.get("news_authors").is_some());
    }
}
