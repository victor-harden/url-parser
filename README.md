# url-parser

A small URL inspector built on `urllib.parse`: show every component, list query
parameters, normalize the URL and flag obvious risks such as credentials in the
URL, non-http schemes or a missing host.

## Features

- Components report: scheme, host, port, path, query, fragment.
- Query parameters as a table or JSON.
- `--normalize`: lowercase scheme/host, remove default ports, sort the query.
- `--check`: risk notes (credentials present, javascript:/data: scheme,
  non-standard port, IP literal host).
- Tests for parsing, normalization and risk checks.

## Installation

```bash
git clone https://github.com/victor-harden/url-parser.git
cd url-parser
```

## Usage

```bash
python3 url_tool.py https://user:pass@example.com:8443/path?a=1&b=2#top
python3 url_tool.py --normalize "HTTPS://Example.COM:443/a?b=2&a=1"
python3 url_tool.py --check "javascript:alert(1)"
python3 url_tool.py --json https://example.com
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
