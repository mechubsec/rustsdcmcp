# rustsdcmcp Roadmap

`rustsdcmcp` currently exposes 73 curated MCP tools: 59 read tools, 14 write
tools, and a generic object reader. Coverage expansion is driven by customer
demand and remains intentionally curated rather than mirroring every upstream
API operation.

## Coverage expansion

The next areas, in expected demand order, are:

1. VPN, site, and IPsec writes through the change-set path.
2. Security-profile writes.
3. Policy assignment and selective deploy.
4. Device onboarding.
5. Image, MNHA, and RMA actions.
6. Template writes.
7. Read-only MCP resources and prompts.

Write tools are registered only when the operator opts in. Every mutation
continues to use the prepare → independent approval → apply change-set
workflow. A benchmark harness is required before making performance claims.

## Blocked upstream

Out-of-band device-change accept/reject is blocked upstream. Security Director
Cloud has no unattended API for this operation, so issues [#135 (accept)](https://github.com/mechubsec/rustsdcmcp/issues/135)
and [#136 (reject)](https://github.com/mechubsec/rustsdcmcp/issues/136) will be
revisited when the vendor provides one.

## Feature requests

Feature requests are welcome as GitHub issues. Please include the expected API
behavior and any customer demand or validation details that can help prioritize
the work.
