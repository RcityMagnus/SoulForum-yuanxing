use crate::security::is_not_banned;
use crate::services::{ForumContext, ForumError, ForumService, ServiceResult};

pub fn fatal_error<S: ForumService>(
    service: &S,
    ctx: &mut ForumContext,
    message: &str,
) -> ServiceResult<()> {
    is_not_banned(service, ctx, false)?;
    ctx.context.set("error_message", message);
    Err(ForumError::Lang(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn fatal_error_sets_message() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        let result = fatal_error(&service, &mut ctx, "denied");
        assert!(result.is_err());
        assert_eq!(ctx.context.string("error_message").unwrap(), "denied");
    }
}
