use crate::services::{ForumContext, ForumService, PersonalMessageFolder, ServiceResult};

pub fn export_profile_pm_data<S: ForumService>(
    service: &S,
    ctx: &mut ForumContext,
) -> ServiceResult<()> {
    if ctx.user_info.is_guest {
        return Ok(());
    }
    let page = service.personal_message_page(
        ctx.user_info.id,
        PersonalMessageFolder::Inbox,
        None,
        0,
        10,
    )?;
    ctx.context.set("pm_export", page.messages);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn export_includes_messages() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 2;
        ctx.user_info.is_guest = false;
        export_profile_pm_data(&service, &mut ctx).unwrap();
        assert!(ctx.context.get("pm_export").is_some());
    }
}
