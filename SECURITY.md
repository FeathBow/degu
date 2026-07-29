# Security policy

## Supported versions

Security fixes target the current `main` branch and the latest published release. Before the first release, this means `main` only. Older releases, commits, and unofficial builds are unsupported.

## Report privately

Do not open a public issue when a report involves any of the following:

- degu moved or permanently removed data outside the confirmed clean or purge set;
- a protected-path, symlink, or filesystem-boundary check can be bypassed;
- degu exposed credentials, sensitive paths, or private infrastructure information to someone who should not receive it;
- reproducing the issue requires details that cannot be safely redacted; or
- the issue describes another exploitable security weakness in degu or one of its dependencies.

Use the repository's **Report a vulnerability** form. If that form is unavailable, open a public issue asking the maintainers to restore a private reporting channel, but include no vulnerability details. If you are unsure whether a report is security-sensitive, report it privately.

## What to include

Include the affected commit, installation method, exact command, observed impact, smallest redacted filesystem layout and reproduction, filesystem type, and relevant operation IDs, trash state, or undo output. Explain whether the behavior occurred on real data, whether it can be reproduced without that data, and whether you know of any active exploitation.

Do not send credentials, unredacted logs, real private file contents, or more identifying path information than the report requires. The maintainer may request more information and will coordinate validation, remediation, credit, and disclosure privately when a vulnerability is confirmed. No fixed response or remediation timeline is offered.

Ordinary bugs that remained within the confirmed target set and can be described with redacted diagnostics belong in the public bug form.
