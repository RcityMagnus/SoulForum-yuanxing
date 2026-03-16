use crate::services::{
    ForumContext, ForumError, ForumService, PersonalMessageDetail, SendPersonalMessage,
    ServiceResult,
};
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct RecipientInput {
    pub to: Vec<String>,
    pub bcc: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RecipientFailure {
    pub target: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct RecipientResolution {
    pub to: Vec<i64>,
    pub bcc: Vec<i64>,
    pub failed: Vec<RecipientFailure>,
}

#[derive(Clone, Debug, Default)]
pub struct PmSendLog {
    pub message_id: Option<i64>,
    pub sent: Vec<i64>,
    pub failed: Vec<RecipientFailure>,
}

pub fn resolve_recipients<S: ForumService>(
    service: &S,
    input: &RecipientInput,
) -> ServiceResult<RecipientResolution> {
    let mut map_target: HashMap<String, i64> = HashMap::new();
    let mut id_cache: HashMap<i64, bool> = HashMap::new();
    let mut name_targets = HashSet::new();

    for value in input.to.iter().chain(input.bcc.iter()) {
        if value.trim().is_empty() {
            continue;
        }
        if value.trim().parse::<i64>().is_err() {
            name_targets.insert(value.to_lowercase());
        }
    }

    if !name_targets.is_empty() {
        let lookups: Vec<String> = name_targets.iter().cloned().collect();
        for record in service.find_members_by_name(&lookups)? {
            map_target.insert(record.name.to_lowercase(), record.id);
        }
    }

    let mut failed = Vec::new();
    let mut to = Vec::new();
    let mut bcc = Vec::new();

    for value in &input.to {
        match find_member_id(service, &mut map_target, &mut id_cache, value) {
            Some(id) => push_unique(&mut to, id),
            None => failed.push(RecipientFailure {
                target: value.clone(),
                reason: "unknown_recipient".into(),
            }),
        }
    }

    for value in &input.bcc {
        match find_member_id(service, &mut map_target, &mut id_cache, value) {
            Some(id) => push_unique(&mut bcc, id),
            None => failed.push(RecipientFailure {
                target: value.clone(),
                reason: "unknown_recipient".into(),
            }),
        }
    }

    Ok(RecipientResolution { to, bcc, failed })
}

pub fn send_pm<S: ForumService>(
    service: &S,
    ctx: &ForumContext,
    recipients: RecipientInput,
    subject: &str,
    body: &str,
) -> ServiceResult<PmSendLog> {
    let resolved = resolve_recipients(service, &recipients)?;
    if resolved.to.is_empty() && resolved.bcc.is_empty() {
        return Err(ForumError::Validation("no_recipients".into()));
    }
    let subject_clean = subject.trim();
    if subject_clean.is_empty() {
        return Err(ForumError::Validation("no_subject".into()));
    }
    let total_recipients = (resolved.to.len() + resolved.bcc.len()) as i64;
    if let Some(limit) = ctx.mod_settings.int("max_pm_recipients") {
        if limit > 0 && total_recipients > limit {
            return Err(ForumError::Validation("pm_too_many_recipients".into()));
        }
    }
    if let Some(per_hour) = ctx.mod_settings.int("pm_posts_per_hour") {
        if per_hour > 0 {
            let since = Utc::now() - Duration::hours(1);
            let sent = service.count_pm_sent_since(ctx.user_info.id, since)?;
            if sent as i64 >= per_hour {
                return Err(ForumError::Validation("pm_rate_limited".into()));
            }
        }
    }

    let request = SendPersonalMessage {
        sender_id: ctx.user_info.id,
        sender_name: ctx.user_info.name.clone(),
        to: resolved.to.clone(),
        bcc: resolved.bcc.clone(),
        subject: subject_clean.to_string(),
        body: body.to_string(),
    };
    let result = service.send_personal_message(request)?;
    service.record_pm_sent(ctx.user_info.id, Utc::now())?;
    Ok(PmSendLog {
        message_id: Some(result.id),
        sent: result.recipient_ids,
        failed: resolved.failed,
    })
}

pub fn load_pm_quote(detail: &PersonalMessageDetail) -> String {
    format!(
        "[quote author={}]\n{}\n[/quote]\n",
        detail.sender_name, detail.body
    )
}

fn push_unique(list: &mut Vec<i64>, value: i64) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn find_member_id<S: ForumService>(
    service: &S,
    name_map: &mut HashMap<String, i64>,
    id_cache: &mut HashMap<i64, bool>,
    target: &str,
) -> Option<i64> {
    if let Ok(id) = target.trim().parse::<i64>() {
        let exists = if let Some(cached) = id_cache.get(&id) {
            *cached
        } else {
            let valid = service.get_member_record(id).ok().flatten().is_some();
            id_cache.insert(id, valid);
            valid
        };
        if exists {
            return Some(id);
        }
    }
    name_map.get(&target.to_lowercase()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn resolve_names_and_ids() {
        let service = InMemoryService::default();
        let recipients = RecipientInput {
            to: vec!["Alice".into(), "2".into()],
            bcc: vec![],
        };
        let resolved = resolve_recipients(&service, &recipients).unwrap();
        assert_eq!(resolved.to.len(), 2);
    }

    #[test]
    fn send_pm_creates_log() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 1;
        ctx.user_info.name = "Alice".into();
        ctx.user_info.permissions.insert("pm_send".into());
        let recipients = RecipientInput {
            to: vec!["2".into()],
            bcc: vec![],
        };
        let log = send_pm(&service, &ctx, recipients, "Hi", "Body").unwrap();
        assert_eq!(log.sent.len(), 1);
    }

    #[test]
    fn recipient_limit_enforced() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 1;
        ctx.user_info.name = "Alice".into();
        ctx.user_info.permissions.insert("pm_send".into());
        ctx.mod_settings.set("max_pm_recipients", 1);
        let recipients = RecipientInput {
            to: vec!["2".into(), "3".into()],
            bcc: vec![],
        };
        let result = send_pm(&service, &ctx, recipients, "Hi", "Body");
        assert!(result.is_err());
    }

    #[test]
    fn per_hour_limit_enforced() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.user_info.id = 1;
        ctx.user_info.name = "Alice".into();
        ctx.user_info.permissions.insert("pm_send".into());
        ctx.mod_settings.set("pm_posts_per_hour", 1);
        let recipients = RecipientInput {
            to: vec!["2".into()],
            bcc: vec![],
        };
        send_pm(&service, &ctx, recipients.clone(), "Hi", "Body").unwrap();
        let err = send_pm(&service, &ctx, recipients, "Second", "Body");
        assert!(err.is_err());
    }
}
