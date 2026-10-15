Bead: beep-35h

# beep-kubeconfig → politeia: STAY

**STAY** — politeia v0.1.0 has full API coverage but lacks beep's IPv6
bracket fix in `parse_addr`, so switching today would break the FIRM
IPv6-only constraint (the controller could not reach a `https://[v6]:6443`
apiserver). Revisit once politeia carries the fix.

## API surface controller/ consumes

- `controller/src/main.rs:37,757,759`: `parse_kubeconfig`, `build_tls_connector`,
  `HyperApiClient` construction.
- `HyperApiClient::request` (event.rs:108, status.rs:137, seed.rs:128,149,
  lease.rs:94,99,113,162, watch.rs:1089),
  `request_with_content_type` (status.rs:166), `watch_stream` (watch.rs:1160).
- `HyperApiClient` type imported in event.rs:10, status.rs:31, watch.rs:18,
  seed.rs:16, lease.rs:24.
- Not used by controller/: `extract_yaml_value`, `drain_watch_buffer`,
  `ClientCreds` fields directly.

## politeia coverage (litehop/politeia @ main, pushed 2026-10-14)

Single file `src/lib.rs` (1095 lines), `Cargo.toml` deps identical to
`kubeconfig/Cargo.toml` (same versions, same features). I diffed it against
`kubeconfig/src/lib.rs`: both are the same code lineage (same timeouts, same
`request`/`request_with_content_type`/`watch_stream`/`drain_watch_buffer`,
same public names). Every symbol listed above exists with an identical
signature. Differences are only:

1. **Gap (blocking):** beep `kubeconfig/src/lib.rs:162-175` strips `[`/`]`
   from the URI host for the TLS server name and re-brackets the dial address
   for v6 literals; politeia has `let host = uri.host()...to_owned()` and
   `format!("{host}:{port}")`. For `https://[fd00:beef:98::3]:6443` politeia
   passes `[fd00:...]` to `try_into::<ServerName>()` (rejected as an invalid
   DNS name) and dials an unbracketed `fd00:...:6443`. Controller never
   connects.
2. **Gap (test):** beep's regression test
   `parse_addr_unbrackets_v6_tls_name_but_keeps_brackets_to_dial`
   (lib.rs:1087-1124) is absent upstream.
3. Cosmetic: doc comments / "u7s-scheduler" naming; beep is crate version
   0.4.0 (path dep), politeia 0.1.0.

Nothing found that politeia fixed and beep lacks (the commit log shows only
README/renovate/rustls-bump commits since extraction on 2026-09-10).

## Dep shape

- Not on crates.io (`GET crates.io/api/v1/crates/politeia` → 404). Only
  option is `politeia = { git = "https://github.com/litehop/politeia", tag = "v0.1.0" }`
  (README usage; tag `v0.1.0` exists). Tag predates renovate commits, so
  pin by tag or `rev`.
- `kubeconfig/src/lib.rs:1-3` records an explicit operator decision
  (2026-09-10) of "no git-dep"; migrating reverses it and needs sign-off.
- Runtime networking: none beyond the same `TcpStream::connect` per request.
  Parsing is local file work; no new runtime assumptions. Build-time dep only.

## Effort if/when GO

Small (~1 hour): swap `beep-kubeconfig` path dep in `controller/Cargo.toml:15`
for the git dep; `s/beep_kubeconfig/politeia/` in 6 files (the 7 `use` lines
above plus the watch.rs doc comments); delete `kubeconfig/` and drop it from
`Cargo.toml:15` workspace members. Zero API diffs. Prerequisite: upstream PR
to politeia porting the lib.rs:162-175 fix plus its test, and a new tag
(v0.1.1), then pin to it.

## Recommendation

STAY now; no follow-on migration bead filed (not a GO). Re-open once politeia
ships the v6 bracket fix and the git-dep policy is reconsidered.
