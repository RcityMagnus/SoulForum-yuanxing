use crate::services::{ForumContext, ServiceResult};

pub fn configure_pm_drafts(
    ctx: &mut ForumContext,
    enable: bool,
    autosave: bool,
) -> ServiceResult<()> {
    ctx.mod_settings.set("drafts_pm_enabled", enable);
    ctx.mod_settings.set("drafts_autosave_enabled", autosave);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ForumContext;

    #[test]
    fn toggle_pm_drafts() {
        let mut ctx = ForumContext::default();
        configure_pm_drafts(&mut ctx, true, false).unwrap();
        assert!(ctx.mod_settings.bool("drafts_pm_enabled"));
        assert!(!ctx.mod_settings.bool("drafts_autosave_enabled"));
    }
}
