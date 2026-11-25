# Third-party notices

IshAstra itself is licensed under Apache-2.0 (see [LICENSE](LICENSE)). It uses
and, in the container image, distributes third-party software under their own
licences. This file is a summary, not legal advice.

## Python dependencies

The wheel and sdist declare their dependencies in `pyproject.toml`; they do not
vendor them. Installed licences come from each distribution (for example
FastAPI/Starlette/Pydantic under MIT or BSD, `cryptography` under Apache-2.0 or
BSD). CI runs a licence-compatibility check over the resolved dependency set.
Inspect a given environment with:

```bash
python -m pip install pip-licenses
pip-licenses --format=markdown
```

## Container image

The runtime image installs Debian packages and downloads tools that are
separate programs, invoked as subprocesses:

| Component | Licence | Source |
|---|---|---|
| Debian base (`python:3.12-slim`) packages, including `nmap`, `sqlmap`, `perl`, `libxml2` | Mixed; mostly GPL-2.0, LGPL, BSD | <https://deb.debian.org/> and `/usr/share/doc/<package>/copyright` in the image |
| Nikto | GPL-2.0 | <https://github.com/sullo/nikto> |
| Nuclei (release binary) | MIT | <https://github.com/projectdiscovery/nuclei> |
| Nuclei templates | MIT | <https://github.com/projectdiscovery/nuclei-templates> |

Distributing the container therefore also distributes GPL-2.0 components. If
you redistribute the image, keep the licence texts and source availability that
those licences require; the Debian archive and the upstream repositories above
are the corresponding sources. IshAstra does not modify those programs.

## Names and trademarks

Nmap, Nuclei, Nikto, SQLMap, Kubernetes, PostgreSQL, Redis and other names are
trademarks of their respective owners. They are used descriptively to identify
compatible tools. See [NOTICE](NOTICE).
