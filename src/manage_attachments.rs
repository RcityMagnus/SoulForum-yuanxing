use crate::services::{ForumContext, ForumError, ForumService, ServiceResult};

/// Remove attachments by id list (used when editing posts and deleting older files).
pub fn remove_attachments<S: ForumService>(
    service: &S,
    attachment_ids: &[i64],
) -> ServiceResult<()> {
    if attachment_ids.is_empty() {
        return Ok(());
    }

    for att in attachment_ids {
        service.delete_attachment(*att)?;
    }
    Ok(())
}

/// Remove all attachments currently assigned to a given message.
pub fn remove_message_attachments<S: ForumService>(
    service: &S,
    message_id: i64,
) -> ServiceResult<()> {
    if message_id == 0 {
        return Err(ForumError::Validation("missing_message".into()));
    }
    let attachments = service.list_message_attachments(message_id)?;
    let ids: Vec<_> = attachments.iter().map(|att| att.id).collect();
    remove_attachments(service, &ids)
}

/// Clean up temporary attachments stored in the context/session when abandoning an edit.
pub fn cleanup_temp_attachments(ctx: &mut ForumContext) {
    if let Some(list) = ctx.session.string("temp_attachments") {
        // Value stored as comma separated ids; clear it to simulate PHP cleanup.
        ctx.session.remove("temp_attachments");
        ctx.context.set("cleanup_message", list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn remove_by_message() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        remove_message_attachments(&service, 1).unwrap();
        assert!(service.list_message_attachments(1).unwrap().is_empty());
        cleanup_temp_attachments(&mut ctx);
    }
}
