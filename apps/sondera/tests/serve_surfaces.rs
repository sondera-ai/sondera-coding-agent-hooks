//! `sondera serve` must expose both gRPC surfaces on the one address.
//!
//! The point of the command is that the harness gRPC service and the console
//! gRPC service share a listener, so this drives a real server process on one
//! port and calls both of them on it — the part that only a live socket can
//! prove.
//!
//! Adjudication itself is exercised with an **empty batch**: the server answers
//! it from the transport without touching Cedar or a guardrail model, so this
//! test stays a test of the wiring rather than of the policy engine.

use sondera_schema::console_v1 as console_pb;
use sondera_schema::console_v1::console_service_client::ConsoleServiceClient;
use sondera_schema::harness_v1 as harness_pb;
use sondera_schema::harness_v1::harness_service_client::HarnessServiceClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Kills the server on the way out, including when an assertion panics.
struct ServerProcess {
    child: Child,
    addr: SocketAddr,
}

impl ServerProcess {
    /// Whatever the server wrote to stderr, for a failure message.
    ///
    /// Only safe to call once the child has exited: it reads the pipe to EOF.
    fn stderr(&mut self) -> String {
        use std::io::Read;

        let mut buffer = String::new();
        if let Some(stderr) = self.child.stderr.as_mut() {
            let _ = stderr.read_to_string(&mut buffer);
        }
        buffer
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The repository's own `.sondera`, so the server loads the committed Cedar
/// policies rather than whatever the developer has in `~/.sondera`.
fn repo_config_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".sondera")
}

/// Claim a free port by binding and releasing it.
///
/// Inherently racy — another process can take the port in between — but it is
/// the only way to hand a chosen address to a child process, and the retry loop
/// in `start_server` reports a lost race as a startup failure rather than a hang.
fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a loopback port should be available")
        .local_addr()
        .expect("a bound listener should have an address")
}

/// Start `sondera serve` against an empty database and wait for it to listen.
fn start_server(db: &std::path::Path) -> ServerProcess {
    let addr = free_addr();
    let child = Command::new(env!("CARGO_BIN_EXE_sondera"))
        .args([
            "serve",
            "--addr",
            &addr.to_string(),
            "--config-dir",
            &repo_config_dir().to_string_lossy(),
            "--db",
            &db.to_string_lossy(),
        ])
        // The server honours `RUST_LOG`, and nothing here drains its pipes while
        // it runs. Dropping the variable holds it to the quiet default, so a
        // developer with `RUST_LOG=debug` exported cannot wedge the child on a
        // full stderr buffer.
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server process should start");

    let mut server = ServerProcess { child, addr };

    // Loading Cedar policies and opening the store takes a moment, so poll the
    // socket instead of sleeping a fixed interval.
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = server
            .child
            .try_wait()
            .expect("server status should be readable")
        {
            panic!(
                "server exited before it listened: {status}\n{}",
                server.stderr()
            );
        }
        if std::net::TcpStream::connect(addr).is_ok() {
            return server;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start listening on {addr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_answers_both_grpc_services_on_one_address() {
    let db_dir = tempfile::tempdir().expect("temp dir");
    let server = start_server(&db_dir.path().join("trajectories.db"));
    let endpoint = format!("http://{}", server.addr);

    // --- harness gRPC ---
    let mut harness = HarnessServiceClient::connect(endpoint.clone())
        .await
        .expect("harness gRPC service should accept a connection");
    let response = harness
        .adjudicates(harness_pb::AdjudicatesRequest { events: vec![] })
        .await
        .expect("adjudication should succeed")
        .into_inner();
    assert!(
        response.events.is_empty(),
        "an empty batch answers with no adjudicated events"
    );

    // --- console gRPC, on the same port ---
    let mut console = ConsoleServiceClient::connect(endpoint)
        .await
        .expect("console gRPC service should accept a connection");
    let agents = console
        .list_agents(console_pb::ListAgentsRequest::default())
        .await
        .expect("listing agents should succeed")
        .into_inner();
    assert!(
        agents.agents.is_empty(),
        "a freshly created database has no agents"
    );
}
