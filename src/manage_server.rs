use crate::services::{ForumContext, ServiceResult};

pub fn set_pm_reporting(ctx: &mut ForumContext, enabled: bool) -> ServiceResult<()> {
    ctx.mod_settings.set("enableReportPM", enabled);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ForumContext;

    #[test]
    fn reporting_toggle() {
        let mut ctx = ForumContext::default();
        set_pm_reporting(&mut ctx, true).unwrap();
        assert!(ctx.mod_settings.bool("enableReportPM"));
    }
}
