use crate::services::{ForumContext, ForumError, ForumService, PollData, ServiceResult};

pub fn create_poll<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    poll: PollData,
) -> ServiceResult<i64> {
    if !service.allowed_to(ctx, "poll_post", None, true) {
        return Err(ForumError::PermissionDenied("poll_post".into()));
    }
    service.create_poll(poll)
}

pub fn remove_poll<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    poll_id: i64,
) -> ServiceResult<()> {
    if !service.allowed_to(ctx, "poll_remove_any", None, true) {
        return Err(ForumError::PermissionDenied("poll_remove_any".into()));
    }
    service.remove_poll(poll_id)
}

pub fn lock_poll<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    poll_id: i64,
    lock: bool,
) -> ServiceResult<()> {
    if !service.allowed_to(ctx, "poll_lock_any", None, true) {
        return Err(ForumError::PermissionDenied("poll_lock_any".into()));
    }
    service.lock_poll(poll_id, lock)
}

pub fn vote<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    poll_id: i64,
    choices: &[i64],
) -> ServiceResult<()> {
    if !service.allowed_to(ctx, "poll_vote", None, false) {
        return Err(ForumError::PermissionDenied("poll_vote".into()));
    }
    service.cast_vote(poll_id, ctx.user_info.id, choices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService, PollOption};

    #[test]
    fn poll_lifecycle() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.permissions.insert("poll_post".into());
        ctx.user_info.permissions.insert("poll_lock_any".into());
        ctx.user_info.permissions.insert("poll_remove_any".into());
        ctx.user_info.permissions.insert("poll_vote".into());
        let poll_id = create_poll(
            &ctx,
            &service,
            PollData {
                id: 0,
                topic_id: 1,
                question: "Question".into(),
                options: vec![PollOption {
                    id: 1,
                    label: "Yes".into(),
                    votes: 0,
                }],
                max_votes: 1,
                change_vote: false,
                guest_vote: false,
            },
        )
        .unwrap();
        lock_poll(&ctx, &service, poll_id, true).unwrap();
        vote(&ctx, &service, poll_id, &[1]).unwrap();
        remove_poll(&ctx, &service, poll_id).unwrap();
    }
}
