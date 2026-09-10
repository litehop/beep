# beep-kubeconfig

Vendored from litehop/u7s@1342a41f5fb41a64c1a08c71914b773f781d4013
`crates/kubeconfig`; re-sync by hand if u7s patches it (beep is a standalone
split; no git-dep per operator decision 2026-09-10).

Parses a kubeconfig file into mTLS credentials, builds a `tokio-rustls`
`TlsConnector` from them, and provides `HyperApiClient`, a minimal HTTP/1.1
client (including `watch_stream` for newline-delimited JSON watches) used to
talk to a Kubernetes API server.
