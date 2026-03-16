use crate::services::{CalendarEvent, ForumContext, ForumError, ForumService, ServiceResult};

pub fn can_link_event<S: ForumService>(ctx: &ForumContext, service: &S) -> ServiceResult<()> {
    if !ctx.mod_settings.bool("cal_enabled") {
        return Err(ForumError::Validation("calendar_disabled".into()));
    }
    if service.can_link_event(ctx.user_info.id)? {
        Ok(())
    } else {
        Err(ForumError::PermissionDenied("calendar_post".into()))
    }
}

pub fn insert_event<S: ForumService>(
    _ctx: &ForumContext,
    service: &S,
    event: CalendarEvent,
) -> ServiceResult<i64> {
    service.insert_event(event)
}

pub fn modify_event<S: ForumService>(
    _ctx: &ForumContext,
    service: &S,
    event_id: i64,
    event: CalendarEvent,
) -> ServiceResult<()> {
    service.modify_event(event_id, event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn create_and_modify_event() {
        let service = InMemoryService::default();
        let ctx = ForumContext::default();
        let id = insert_event(
            &ctx,
            &service,
            CalendarEvent {
                id: None,
                board_id: 1,
                topic_id: 1,
                title: "Launch".into(),
                location: "Online".into(),
                member_id: 1,
            },
        )
        .unwrap();
        modify_event(
            &ctx,
            &service,
            id,
            CalendarEvent {
                id: Some(id),
                board_id: 1,
                topic_id: 1,
                title: "Updated".into(),
                location: "Offline".into(),
                member_id: 1,
            },
        )
        .unwrap();
    }
}
