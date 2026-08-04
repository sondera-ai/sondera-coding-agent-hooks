//! Wire adaptation for the two streaming RPCs.
//!
//! The store hands back domain streams
//! (`Stream<Item = Result<T, StoreError>>`); tonic wants
//! `Stream<Item = Result<Wire, Status>>`. [`MappedStream`] is the one-item
//! adapter between them, kept as a named type because tonic's generated trait
//! requires the response stream to be a concrete associated type.

use crate::service::console_error;
use futures_core::Stream;
use sondera_types::StoreError;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Status;

/// Projects each item of a domain stream into its wire shape, mapping store
/// errors to gRPC statuses.
///
/// `S` is required to be [`Unpin`] (the store's boxed streams are) so the
/// adapter needs no pin projection, and the projection is a plain `fn` pointer
/// rather than a closure so the whole type stays `Unpin` and nameable.
pub struct MappedStream<S, T, U> {
    inner: S,
    project: fn(&T) -> U,
}

impl<S, T, U> MappedStream<S, T, U> {
    pub(crate) fn new(inner: S, project: fn(&T) -> U) -> Self {
        Self { inner, project }
    }
}

impl<S, T, U> Stream for MappedStream<S, T, U>
where
    S: Stream<Item = Result<T, StoreError>> + Unpin,
    T: Unpin,
    U: Unpin,
{
    type Item = Result<U, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok((this.project)(&item)))),
            // A gRPC stream terminates on an error status, which matches how the
            // store's polling tails behave: they send the failure and stop.
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(console_error(error)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
