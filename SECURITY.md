# Security policy

Volc Agent Launchpad is a hackathon proof of concept. Only the latest revision
on the default branch is supported.

## Report a vulnerability

Send the repository owner or event organizer the affected revision,
reproduction steps, impact, and suggested mitigation. Do not publish
credentials, personal data, or exploit details in an issue.

## Known limitations

- Shared demo token; no user identity, authorization, RBAC, or tenant isolation
- No CSRF protection
- No per-Agent container boundary in ECS mode
- Ordinary local containers, not hardened multi-tenant sandboxes
- Broad outbound network access
- Prompt-triggered command and file execution
- Ark key available to the server and active Runtime container
- Ark key stored in Terraform POC state
- `SHADOW_ALLOW_UNCONFINED=1` with `RUNTIME_PROVIDER=local-process` runs the turn as a
  child process of the server with no filesystem jail. Every /api route still answers
  the operator only, and settling a review there refuses a bare loopback caller because
  loopback cannot tell the agent from the operator, but be clear about what that is worth:
  a turn on that host can already read and delete the journal and the workspaces directly,
  so the boundary does not stop a local agent, it stops the control plane from vouching
  for one. Set `APP_AUTH_TOKEN` to settle reviews in that mode, and run
  `RUNTIME_PROVIDER=container` when the boundary has to hold.
- Every record names the principal the server authenticated, never a name the caller typed.
  `x-actor` arrives from the caller like any other header, so the operator hook overwrites it
  with that principal before any route runs, and an approval, a capability grant and its
  revocation all carry the same name. What the name is worth is bounded by the first line of
  this list: the token is shared, so every holder of it is one principal,
  `operator:` followed by the first 12 hex characters of its sha256, and the log cannot tell
  two people holding the same token apart. With no token configured the name is `operator` and
  means only that the caller reached this machine's loopback.

## Safe use

- Use a dedicated development machine or disposable ECS instance.
- Use a scoped, revocable Ark key and a unique `APP_AUTH_TOKEN`.
- Keep local use on loopback and restrict ECS Web and SSH CIDRs.
- Add HTTPS before sending the shared token over an untrusted network.
- Never mount production data or provide Volcengine account AK/SK to Agents.
- Stop the POC, destroy test resources, and revoke keys after the event.

Codex uses `workspace-write` when Landlock is available. On unsupported kernels,
startup warns and relies on the outer Docker or rootless Podman boundary. This
fallback is not tenant isolation.
