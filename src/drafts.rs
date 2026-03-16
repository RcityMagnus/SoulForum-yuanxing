use crate::services::{
    DraftStorage, ForumContext, ForumError, ForumService, PmDraftRecord, ServiceResult,
};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, Default)]
pub struct DraftOptions {
    pub id: Option<i64>,
    pub topic_id: Option<i64>,
    pub board_id: Option<i64>,
    pub subject: String,
    pub body: String,
    pub icon: String,
    pub smileys_enabled: bool,
    pub locked: bool,
    pub sticky: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DraftRecord {
    pub id: i64,
    pub topic_id: i64,
    pub board_id: i64,
    pub subject: String,
    pub body: String,
    pub icon: String,
    pub smileys_enabled: bool,
    pub locked: bool,
    pub sticky: bool,
    pub poster_time: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
pub struct PmDraftOptions {
    pub id: Option<i64>,
    pub subject: String,
    pub body: String,
    pub to: Vec<i64>,
    pub bcc: Vec<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct PmDraftSummary {
    pub id: i64,
    pub subject: String,
    pub body: String,
    pub to: Vec<i64>,
    pub bcc: Vec<i64>,
    pub saved_at: DateTime<Utc>,
}

pub fn save_draft<S: ForumService>(
    ctx: &mut ForumContext,
    service: &S,
    options: DraftOptions,
) -> ServiceResult<DraftRecord> {
    if !ctx.mod_settings.bool("drafts_post_enabled") {
        return Err(ForumError::Validation("drafts_disabled".into()));
    }
    if !service.allowed_to(ctx, "post_draft", None, true) {
        return Err(ForumError::PermissionDenied("post_draft".into()));
    }

    let subject = options.subject.trim();
    if subject.is_empty() {
        return Err(ForumError::Validation("draft_no_subject".into()));
    }

    let board_id = options
        .board_id
        .or(ctx.board_id)
        .ok_or_else(|| ForumError::Validation("draft_missing_board".into()))?;

    let mut record = DraftStorage {
        id: options.id.unwrap_or(0),
        board_id,
        topic_id: options.topic_id.unwrap_or(0),
        subject: subject.to_string(),
        body: options.body.clone(),
        icon: options.icon.clone(),
        smileys_enabled: options.smileys_enabled,
        locked: options.locked,
        sticky: options.sticky,
        poster_time: Utc::now(),
    };

    let id = service.save_draft_record(record.clone())?;
    record.id = id;

    Ok(DraftRecord {
        id,
        topic_id: record.topic_id,
        board_id: record.board_id,
        subject: record.subject,
        body: record.body,
        icon: record.icon,
        smileys_enabled: record.smileys_enabled,
        locked: record.locked,
        sticky: record.sticky,
        poster_time: record.poster_time,
    })
}

pub fn delete_draft<S: ForumService>(service: &S, draft_id: i64) -> ServiceResult<()> {
    service.delete_draft(draft_id)
}

pub fn save_pm_draft<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    options: PmDraftOptions,
) -> ServiceResult<PmDraftSummary> {
    if !ctx.mod_settings.bool("drafts_pm_enabled") {
        return Err(ForumError::Validation("pm_drafts_disabled".into()));
    }
    if !service.allowed_to(ctx, "pm_draft", None, false) {
        return Err(ForumError::PermissionDenied("pm_draft".into()));
    }
    let subject = options.subject.trim();
    if subject.is_empty() {
        return Err(ForumError::Validation("draft_no_subject".into()));
    }
    let mut record = PmDraftRecord {
        id: options.id.unwrap_or(0),
        owner_id: ctx.user_info.id,
        subject: subject.to_string(),
        body: options.body,
        to: options.to,
        bcc: options.bcc,
        saved_at: Utc::now(),
    };
    let id = service.save_pm_draft(record.clone())?;
    record.id = id;
    Ok(PmDraftSummary {
        id,
        subject: record.subject,
        body: record.body,
        to: record.to,
        bcc: record.bcc,
        saved_at: record.saved_at,
    })
}

pub fn list_pm_drafts<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    start: usize,
    limit: usize,
) -> ServiceResult<Vec<PmDraftSummary>> {
    Ok(service
        .list_pm_drafts(ctx.user_info.id, start, limit)?
        .into_iter()
        .map(|draft| PmDraftSummary {
            id: draft.id,
            subject: draft.subject,
            body: draft.body,
            to: draft.to,
            bcc: draft.bcc,
            saved_at: draft.saved_at,
        })
        .collect())
}

pub fn load_pm_draft<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    draft_id: i64,
) -> ServiceResult<Option<PmDraftSummary>> {
    Ok(service
        .read_pm_draft(ctx.user_info.id, draft_id)?
        .map(|draft| PmDraftSummary {
            id: draft.id,
            subject: draft.subject,
            body: draft.body,
            to: draft.to,
            bcc: draft.bcc,
            saved_at: draft.saved_at,
        }))
}

pub fn delete_pm_draft<S: ForumService>(
    ctx: &ForumContext,
    service: &S,
    draft_id: i64,
) -> ServiceResult<()> {
    service.delete_pm_draft(ctx.user_info.id, draft_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn save_and_delete_draft() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.mod_settings.set("drafts_post_enabled", true);
        ctx.board_id = Some(1);
        ctx.user_info.permissions.insert("post_draft".into());

        let draft = save_draft(
            &mut ctx,
            &service,
            DraftOptions {
                subject: "Draft subject".into(),
                body: "Draft body".into(),
                board_id: Some(1),
                ..DraftOptions::default()
            },
        )
        .unwrap();

        delete_draft(&service, draft.id).unwrap();
    }

    #[test]
    fn pm_draft_roundtrip() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 2;
        ctx.user_info.permissions.insert("pm_draft".into());
        ctx.mod_settings.set("drafts_pm_enabled", true);

        let saved = save_pm_draft(
            &ctx,
            &service,
            PmDraftOptions {
                subject: "Hello".into(),
                body: "Body".into(),
                to: vec![1],
                ..PmDraftOptions::default()
            },
        )
        .unwrap();
        let drafts = list_pm_drafts(&ctx, &service, 0, 10).unwrap();
        assert_eq!(drafts.len(), 1);
        delete_pm_draft(&ctx, &service, saved.id).unwrap();
    }
}
