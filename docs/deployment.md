# Deployment

## Production hardening

`sondera serve` binds `127.0.0.1:50051` by default, so it is reachable only from
the local host. Whichever process binds the address first controls adjudication
for all hook clients, and neither surface authenticates its caller: adjudication
is plain HTTP/2 gRPC, while the console returns the whole local store and
exposes agent deletion.

Keep the bind address on loopback (or a private interface) and do not expose it
publicly without an authenticating proxy in front. Point hook clients at the
harness with `SONDERA_HARNESS_ENDPOINT`.

`sondera mcp` binds nothing: it speaks JSON-RPC over the stdio pipes of whatever
client launched it, so its reach is that client's.

## Fail-closed behaviour

A hook that cannot reach the harness denies preventive events; it never proceeds
unadjudicated. Losing the server therefore blocks the agent rather than silently
ungoverning it.

## Data handling

With the LLM guardrails enabled, event content is sent to the configured
provider — see [Configuration](configuration.md#what-gets-sent-to-the-provider)
for exactly what leaves the host.
