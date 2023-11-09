# kmgm
**:closed_lock_with_key::link: Generate certs for your cluster, easy way**

[![Build Status][gh-actions-badge]][gh-actions]
[![go report][go-report-badge]][go-report]

kmgm is a [certificate authority](https://en.wikipedia.org/wiki/Certificate_authority) with focus on its ease of use. Setup certificates and deploy to your cluster in minutes!

![demo session][demo-session-svg]

## Installation

Linux, macOS:

Install a pre-built binary of the latest version:

```sh
curl -L https://github.com/IPA-CyberLab/kmgm/releases/latest/download/kmgm_$(uname)_$(uname -m).tar.gz | sudo tar zx -C /usr/local/bin kmgm
```

Install a pre-built binary of a specific version:

```sh
VER=0.3.0; curl -L https://github.com/IPA-CyberLab/kmgm/releases/download/v${VER}/kmgm_$(uname)_$(uname -m).tar.gz | sudo tar zx -C /usr/local/bin kmgm
```

or, to build it yourself:

```sh
go get -v -u github.com/IPA-CyberLab/kmgm/cmd/...
```

## Quick start

Setup a new CA:
```sh
kmgm setup
```

Issue a new certificate:
```sh
kmgm issue
```

## Tutorials

- [Setup nginx with kmgm issued certificate](https://github.com/IPA-CyberLab/kmgm/blob/master/docs/tutorials/nginx/README.md)

## License

kmgm is licensed under Apache license version 2.0. See [LICENSE](https://github.com/IPA-CyberLab/kmgm/blob/master/LICENSE) for more information.

<!-- Markdown link & img dfn's -->
[go-report-badge]: https://goreportcard.com/badge/github.com/IPA-CyberLab/kmgm
[go-report]: https://goreportcard.com/report/github.com/IPA-CyberLab/kmgm
[gh-actions-badge]: https://github.com/IPA-CyberLab/kmgm/workflows/Test%20and%20Release/badge.svg
[gh-actions]: https://github.com/IPA-CyberLab/kmgm/actions
[demo-session-svg]: https://raw.githubusercontent.com/IPA-CyberLab/kmgm/master/docs/demo.svg
