use crate::services::{ForumContext, ForumService, PmPreferenceState, ServiceResult};

pub fn initialize_pm_settings<S: ForumService>(
    service: &S,
    ctx: &mut ForumContext,
) -> ServiceResult<()> {
    if ctx.user_info.is_guest {
        return Ok(());
    }
    service.save_pm_preferences(
        ctx.user_info.id,
        &PmPreferenceState {
            receive_from: 0,
            notify_level: 0,
        },
    )?;
    service.set_pm_ignore_list(ctx.user_info.id, &[])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn register_sets_defaults() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 5;
        ctx.user_info.is_guest = false;
        initialize_pm_settings(&service, &mut ctx).unwrap();
        let prefs = service.get_pm_preferences(5).unwrap();
        assert_eq!(prefs.receive_from, 0);
    }
}
