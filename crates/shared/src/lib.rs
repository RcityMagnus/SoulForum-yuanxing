pub mod dto {
    pub mod auth;
    pub mod board;
}
pub mod error;

pub use dto::auth::{
    AuthMeResponse, AuthResponse, AuthUser, LoginRequest, RegisterRequest,
    RegisterResponse,
};
pub use dto::board::{Board, BoardsResponse, CreateBoardPayload};
pub use error::{ApiError, ErrorCode};
