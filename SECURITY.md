English | [日本語](SECURITY.ja.md)

# Security policy

Please report vulnerabilities in ZET (zero-exec-triage) itself through GitHub's private reporting, not through a public issue.

1. Open the repository's **Security** tab
2. Choose **Report a vulnerability**

## Scope

- The latest main branch (fixes are not made to past versions)

What we want reported (examples):

- A way around the invariants (I-1 to I-13) of the remediation plan (remediation-plan.json)
- Input content that makes ZET start an external process

What we accept as public issues:

- Bugs that are not vulnerabilities (wrong decisions, better error messages, and so on)

## Response

This project is maintained by one person, so responses are made as far as possible. There is no guaranteed response time. After a fix is published, the report and the fix are recorded in the CHANGELOG (the reporter's name is included if they wish).
