//! `sondera mcp` must speak MCP over its own stdio pipes.
//!
//! An MCP client launches the command as a subprocess and talks JSON-RPC over
//! newline-delimited stdout, so the wiring only holds if the real binary answers
//! an `initialize` on stdout with nothing else mixed into the stream. That is
//! what this drives: the actual process, the actual pipes.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Kills the server on the way out, including when an assertion panics.
struct ServerProcess(Child);

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The server must come up with nothing listening on the console endpoint.
///
/// This is the regression the gRPC client exists for: the console tools used to
/// open the trajectory database directly, which meant `sondera mcp` could not
/// start at all next to a running `sondera serve` — the store admits one
/// process at a time. Cedar authoring never needed the store, so the endpoint
/// here is deliberately dead: reaching `initialize` and `tools/list` against it
/// proves the console is dialed lazily and cannot gate startup.
#[test]
fn mcp_exposes_unary_console_tools_over_stdio() {
    let child = Command::new(env!("CARGO_BIN_EXE_sondera"))
        // Port 1 needs no privileges to *dial* and has nothing behind it.
        .args(["mcp", "--endpoint", "http://127.0.0.1:1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Logs belong on stderr and nothing here drains that pipe, so hold the
        // server to its quiet default: a developer with `RUST_LOG=debug`
        // exported must not be able to wedge the child on a full buffer.
        .env_remove("RUST_LOG")
        .stderr(Stdio::null())
        .spawn()
        .expect("MCP server process should start");
    let mut server = ServerProcess(child);

    let stdout = server.0.stdout.take().expect("stdout is piped");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    let stdin = server.0.stdin.as_mut().expect("stdin is piped");
    stdin
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"mcp-stdio-test\",\"version\":\"0\"}}}\n",
        )
        .expect("the initialize request should reach the server");

    let response = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("the server should answer the initialize request")
        .expect("stdout should be readable");
    assert!(response.contains("\"serverInfo\""), "got: {response}");

    stdin
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
        )
        .expect("the tool-list request should reach the server");
    let tools = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("the server should list its tools")
        .expect("stdout should be readable");

    for name in [
        "list_agents",
        "get_agent",
        "update_agent",
        "analyze_agents",
        "delete_agent",
        "get_trajectory",
        "list_trajectory_events",
        "list_trajectories",
    ] {
        assert!(
            tools.contains(&format!("\"name\":\"{name}\"")),
            "missing {name}: {tools}"
        );
    }
    for name in [
        "stream_trajectories",
        "stream_trajectory",
        "batch_get_trajectory_sparklines",
    ] {
        assert!(
            !tools.contains(&format!("\"name\":\"{name}\"")),
            "unexpected {name}: {tools}"
        );
    }
}
