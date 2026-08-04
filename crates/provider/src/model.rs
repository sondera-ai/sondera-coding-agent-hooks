//! Object-safe completion-model trait used to erase provider-specific model
//! types behind a single trait object.

use async_trait::async_trait;
use rig::completion::{
    self, CompletionError, CompletionRequest, CompletionResponse, GetTokenUsage,
};

/// An object-safe view over a rig [`completion::CompletionModel`].
///
/// Each rig provider exposes its own completion model with distinct `Response`
/// and `StreamingResponse` associated types, so heterogeneous provider models
/// cannot share a single trait object directly. This trait erases those types
/// by discarding the provider-specific raw response, allowing a
/// [`Client`](crate::Client) to return one `Box<dyn DynCompletionModel>`
/// regardless of which provider was selected at runtime.
#[async_trait]
pub trait DynCompletionModel: Send + Sync {
    /// Run a completion request, discarding the provider-specific raw response.
    async fn completion(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse<()>, CompletionError>;
}

/// Any concrete rig completion model is usable as a [`DynCompletionModel`].
#[async_trait]
impl<M> DynCompletionModel for M
where
    M: completion::CompletionModel + Send + Sync,
    M::StreamingResponse: Clone + Unpin + GetTokenUsage + 'static,
{
    async fn completion(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse<()>, CompletionError> {
        completion::CompletionModel::completion(self, request)
            .await
            .map(|response| CompletionResponse {
                choice: response.choice,
                usage: response.usage,
                raw_response: (),
                message_id: response.message_id,
            })
    }
}
