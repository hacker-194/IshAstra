# Support

IshAstra is a community-maintained project. Support is best-effort; there is no
SLA, paid support contract, or guaranteed response time.

## Where to ask

| Topic | Channel |
|---|---|
| Usage questions, bug reports, feature requests | [GitHub Issues](https://github.com/hacker-194/IshAstra/issues) |
| Security vulnerabilities | **Private advisory only:** <https://github.com/hacker-194/IshAstra/security/advisories/new>. Do not open a public issue. |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md) |

## Before opening an issue

- Check the [documentation index](docs/index.md), [Limitations](README.md#limitations)
  and [SECURITY.md](SECURITY.md#deliberate-limitations).
- Run `ishastra --version` and include it.
- Include the command, the expected and actual result, and relevant logs with
  secrets, hostnames and scope documents redacted.
- For scan failures, say whether the egress gateway was configured and which
  queue mode was in use.

## Supported versions

- IshAstra 4.0.x
- Python 3.12, 3.13 and 3.14
- Linux is the tested platform; other platforms are best-effort

## Not supported

- Testing systems you are not authorized to test. See
  [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).
- Recovering data after an operator deletes keys or evidence without a backup.
