use crate::services::{ForumContext, ForumService, ServiceResult};

pub fn load_pm_state<S: ForumService>(service: &S, ctx: &mut ForumContext) -> ServiceResult<()> {
    if ctx.user_info.is_guest {
        return Ok(());
    }
    let ignore = service.get_pm_ignore_list(ctx.user_info.id)?;
    ctx.user_info.pm_ignore_list = ignore;
    ctx.user_info.buddies = service.get_buddy_list(ctx.user_info.id)?;
    let prefs = service.get_pm_preferences(ctx.user_info.id)?;
    ctx.user_info.pm_receive_from = prefs.receive_from;
    ctx.user_info.pm_prefs = prefs.notify_level;
    Ok(())
}
