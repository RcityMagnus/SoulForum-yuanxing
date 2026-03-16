use crate::personal_messages::pm_link;
use crate::pm_context::load_pm_state;
use crate::services::{ForumContext, ForumService, ServiceResult};

pub fn view_profile<S: ForumService>(
    service: &S,
    ctx: &mut ForumContext,
    member_id: i64,
) -> ServiceResult<()> {
    load_pm_state(service, ctx)?;
    ctx.context.set("view_member", member_id);
    ctx.context
        .set("can_send_pm", pm_link(ctx, member_id).is_some());
    ctx.context.set("send_pm_url", pm_link(ctx, member_id));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn profile_view_pm_link() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 2;
        ctx.user_info.is_guest = false;
        ctx.user_info.permissions.insert("pm_send".into());
        ctx.scripturl = "https://forum.local".into();
        view_profile(&service, &mut ctx, 1).unwrap();
        assert!(ctx.context.get("send_pm_url").is_some());
    }
}
