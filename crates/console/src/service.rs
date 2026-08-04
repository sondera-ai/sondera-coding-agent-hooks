//! gRPC adapter for the console service.
//!
//! Unary RPCs translate protobuf requests into domain inputs for
//! [`ConsoleHandlers`] and encode its domain results back to protobuf. The two
//! streaming RPCs remain transport-specific because their response stream types
//! are part of tonic's generated trait.

use crate::handlers::{AgentView, ConsoleHandlers};
use crate::query;
use crate::stream::MappedStream;
use sondera_schema::console_v1 as pb;
use sondera_schema::console_v1::console_service_server::{ConsoleService, ConsoleServiceServer};
use sondera_schema::names::{agent_id_from_name, trajectory_id_from_name};
use sondera_types::{
    Event, ReaderWriter, StoreError, Trajectory, TrajectoryEventStream, TrajectoryStream,
    ValidationError,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// tonic service adapter over the shared console handlers.
pub struct ConsoleGrpcService<S> {
    handlers: ConsoleHandlers<S>,
}

impl<S> ConsoleGrpcService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            handlers: ConsoleHandlers::new(store),
        }
    }
}

fn validation_error(error: ValidationError) -> Status {
    Status::invalid_argument(error.to_string())
}

pub(crate) fn console_error(error: StoreError) -> Status {
    match error {
        StoreError::NotFound(message) => Status::not_found(message),
        StoreError::AlreadyExists(message) => Status::already_exists(message),
        StoreError::InvalidArgument(message) => Status::invalid_argument(message),
        StoreError::FailedPrecondition(message) => Status::failed_precondition(message),
        other => {
            tracing::error!(error = %other, "console store failure");
            Status::internal("internal error")
        }
    }
}

fn agent_summary(view: &AgentView) -> pb::AgentSummary {
    pb::AgentSummary {
        sparkline: view.sparkline.as_ref().map(pb::TrajectorySparkline::from),
        ..pb::AgentSummary::from(&view.activity)
    }
}

#[tonic::async_trait]
impl<S: ReaderWriter + 'static> ConsoleService for ConsoleGrpcService<S> {
    type StreamTrajectoriesStream =
        MappedStream<TrajectoryStream, Trajectory, pb::TrajectorySummary>;
    type StreamTrajectoryStream = MappedStream<TrajectoryEventStream, Event, pb::TrajectoryEvent>;

    async fn list_agents(
        &self,
        request: Request<pb::ListAgentsRequest>,
    ) -> Result<Response<pb::ListAgentsResponse>, Status> {
        let request = request.into_inner();
        let query = query::agents(
            request.page_size,
            &request.page_token,
            &request.filter,
            &request.order_by,
        )
        .map_err(validation_error)?;
        let page = self
            .handlers
            .list_agents(&query)
            .await
            .map_err(console_error)?;
        Ok(Response::new(pb::ListAgentsResponse {
            agents: page.items.iter().map(agent_summary).collect(),
            next_page_token: query::next_page_token(query.offset, page.items.len(), page.total),
            total_size: page.total as i32,
        }))
    }

    async fn get_agent(
        &self,
        request: Request<pb::GetAgentRequest>,
    ) -> Result<Response<pb::Agent>, Status> {
        let name = request.into_inner().name;
        let id = agent_id_from_name(&name).map_err(validation_error)?;
        let view = self.handlers.get_agent(id).await.map_err(console_error)?;
        Ok(Response::new(pb::Agent {
            name,
            summary: Some(agent_summary(&view)),
        }))
    }

    async fn update_agent(
        &self,
        request: Request<pb::UpdateAgentRequest>,
    ) -> Result<Response<pb::AgentSummary>, Status> {
        let agent = request
            .into_inner()
            .agent
            .ok_or_else(|| Status::invalid_argument("agent is required"))?;
        let id = agent_id_from_name(&agent.name).map_err(validation_error)?;
        let view = self
            .handlers
            .update_agent(id)
            .await
            .map_err(console_error)?;
        Ok(Response::new(agent_summary(&view)))
    }

    async fn analyze_agents(
        &self,
        request: Request<pb::AnalyzeAgentsRequest>,
    ) -> Result<Response<pb::AgentStats>, Status> {
        let filter = query::agent_filter(&request.into_inner().filter).map_err(validation_error)?;
        let stats = self
            .handlers
            .analyze_agents(&filter)
            .await
            .map_err(console_error)?;
        Ok(Response::new(pb::AgentStats::from(&stats)))
    }

    async fn delete_agent(
        &self,
        request: Request<pb::DeleteAgentRequest>,
    ) -> Result<Response<()>, Status> {
        let name = request.into_inner().name;
        let id = agent_id_from_name(&name).map_err(validation_error)?;
        self.handlers
            .delete_agent(id)
            .await
            .map_err(console_error)?;
        Ok(Response::new(()))
    }

    async fn get_trajectory(
        &self,
        request: Request<pb::GetTrajectoryRequest>,
    ) -> Result<Response<pb::TrajectorySummary>, Status> {
        let name = request.into_inner().name;
        let id = trajectory_id_from_name(&name).map_err(validation_error)?;
        let trajectory = self
            .handlers
            .get_trajectory(id)
            .await
            .map_err(console_error)?;
        Ok(Response::new(pb::TrajectorySummary::from(&trajectory)))
    }

    async fn list_trajectory_events(
        &self,
        request: Request<pb::ListTrajectoryEventsRequest>,
    ) -> Result<Response<pb::ListTrajectoryEventsResponse>, Status> {
        let request = request.into_inner();
        let id = trajectory_id_from_name(&request.trajectory).map_err(validation_error)?;
        let offset = query::offset(&request.page_token);
        let page = self
            .handlers
            .list_trajectory_events(id, offset, query::limit(request.page_size))
            .await
            .map_err(console_error)?;
        Ok(Response::new(pb::ListTrajectoryEventsResponse {
            details: page
                .items
                .iter()
                .map(pb::TrajectoryEventDetail::from)
                .collect(),
            next_page_token: query::next_page_token(offset, page.items.len(), page.total),
            total_size: page.total as i32,
        }))
    }

    async fn list_trajectories(
        &self,
        request: Request<pb::ListTrajectoriesRequest>,
    ) -> Result<Response<pb::ListTrajectoriesResponse>, Status> {
        let request = request.into_inner();
        let query = query::trajectories(
            request.page_size,
            &request.page_token,
            &request.filter,
            &request.order_by,
        )
        .map_err(validation_error)?;
        let page = self
            .handlers
            .list_trajectories(&query)
            .await
            .map_err(console_error)?;
        Ok(Response::new(pb::ListTrajectoriesResponse {
            trajectories: page.items.iter().map(pb::TrajectorySummary::from).collect(),
            next_page_token: query::next_page_token(query.offset, page.items.len(), page.total),
            total_size: page.total as i32,
        }))
    }

    async fn batch_get_trajectory_sparklines(
        &self,
        request: Request<pb::BatchGetTrajectorySparklinesRequest>,
    ) -> Result<Response<pb::BatchGetTrajectorySparklinesResponse>, Status> {
        let ids = request
            .into_inner()
            .names
            .iter()
            .map(|name| trajectory_id_from_name(name).map(ToString::to_string))
            .collect::<Result<Vec<_>, _>>()
            .map_err(validation_error)?;
        let sparklines = self
            .handlers
            .batch_get_trajectory_sparklines(&ids)
            .await
            .map_err(console_error)?;
        Ok(Response::new(pb::BatchGetTrajectorySparklinesResponse {
            sparklines: sparklines
                .iter()
                .map(pb::TrajectorySparkline::from)
                .collect(),
        }))
    }

    async fn stream_trajectories(
        &self,
        request: Request<pb::StreamTrajectoriesRequest>,
    ) -> Result<Response<Self::StreamTrajectoriesStream>, Status> {
        let filter =
            query::trajectory_filter(&request.into_inner().filter).map_err(validation_error)?;
        let stream = self
            .handlers
            .store()
            .stream_trajectories(&filter)
            .await
            .map_err(console_error)?;
        Ok(Response::new(MappedStream::new(stream, |trajectory| {
            pb::TrajectorySummary::from(trajectory)
        })))
    }

    async fn stream_trajectory(
        &self,
        request: Request<pb::StreamTrajectoryRequest>,
    ) -> Result<Response<Self::StreamTrajectoryStream>, Status> {
        let trajectory = request.into_inner().trajectory;
        let id = trajectory_id_from_name(&trajectory).map_err(validation_error)?;
        let stream = self
            .handlers
            .store()
            .stream_trajectory(id)
            .await
            .map_err(console_error)?;
        Ok(Response::new(MappedStream::new(stream, |event| {
            pb::TrajectoryEvent::from(event)
        })))
    }
}

/// Build the tonic service over `store`, with this transport's message-size
/// limits applied.
pub fn grpc_service<S>(store: Arc<S>) -> ConsoleServiceServer<ConsoleGrpcService<S>>
where
    S: ReaderWriter + 'static,
{
    ConsoleServiceServer::new(ConsoleGrpcService::new(store))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES)
}

/// Serve the console read surface over gRPC on `addr` until the process exits.
pub async fn serve<S>(store: Arc<S>, addr: SocketAddr) -> Result<(), tonic::transport::Error>
where
    S: ReaderWriter + 'static,
{
    tracing::info!("Console gRPC server listening on {addr}");
    tonic::transport::Server::builder()
        .add_service(grpc_service(store))
        .serve(addr)
        .await
}
