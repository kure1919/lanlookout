# Security policy

## Supported versions

Only the latest state of the `main` branch is supported. There are no
releases and no backports; this is a best-effort "utakata" project and
maintenance may stop at any time.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** for this
repository (Security tab → "Report a vulnerability"). Do not open a
public issue for a vulnerability, and do not include credentials, real
MAC addresses, or network details of any live deployment in a report.

Reports are read on a best-effort basis. There is no response-time
commitment, but reports that show a concrete path to harm — for
example a way for a non-root local user to obtain a ban or release
they should not be able to cause, or a way for detection data to be
treated as instructions by the verification loop — are taken
seriously.

## Scope notes

lanlookout is a read-only monitor. It assumes the host it runs on and
its SSH access to the Pi-hole nodes are trusted local components.
The only outbound actions it takes are posting notifications and —
when the operator enables the bridge — reporting events to the
operator's own activeban host over an SSH forced command. Findings
that require an already-privileged local account to exploit are
generally out of scope. A way for a monitored device to influence
*another* device's baseline, identity, or reports (for example via
crafted DNS names) would be in scope.
