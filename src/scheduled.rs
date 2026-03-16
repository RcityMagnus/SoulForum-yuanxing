use crate::services::{ForumService, ServiceResult};

pub fn run_scheduled_tasks<S: ForumService>(service: &S) -> ServiceResult<()> {
    let expired = service.clean_expired_bans()?;
    if expired > 0 {
        service.log_action("clean_bans", None, &serde_json::json!({"expired": expired}))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::InMemoryService;

    #[test]
    fn scheduled_clean_runs() {
        let service = InMemoryService::default();
        run_scheduled_tasks(&service).unwrap();
    }
}
