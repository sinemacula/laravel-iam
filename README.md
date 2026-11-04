<h1 align="center">Laravel IAM</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-iam.svg)](https://packagist.org/packages/sinemacula/laravel-iam)
[![PHP Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-iam/php.svg)](https://packagist.org/packages/sinemacula/laravel-iam)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-iam/laravel/framework.svg?label=laravel)](https://packagist.org/packages/sinemacula/laravel-iam)
[![Build Status](https://github.com/sinemacula/laravel-iam/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-iam/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-iam/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-iam/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-iam/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-iam)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-iam/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-iam)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-iam.svg)](https://packagist.org/packages/sinemacula/laravel-iam)
[![License](https://img.shields.io/github/license/sinemacula/laravel-iam.svg)](LICENSE)

</div>

Identity and access management for Laravel: installs the authentication, authorization, MFA, SSO and audit log
packages and binds them together. Each of the five works alone; this package provides the glue between them: it binds each one's contracts to the others' services, translates between their shapes,
maps their events to the audit trail and checks that the whole is configured safely.

| Package                             | Owns                                                                                        |
|-------------------------------------|---------------------------------------------------------------------------------------------|
| `sinemacula/laravel-authentication` | Who the caller is: identities, principals, sessions, credentials and tokens                 |
| `sinemacula/laravel-authorization`  | What the principal may do: roles, permissions, policies and their evaluation                |
| `sinemacula/laravel-mfa`            | Further factors, their enrolment, recovery codes, the factor combination policy and step-up |
| `sinemacula/laravel-sso`            | Sign-in through a tenant's own identity provider, over SAML 2.0 or OpenID Connect           |
| `sinemacula/laravel-audit-log`      | Recording security-relevant activity                                                        |

Each package references no other and exposes its own contracts with defaults that fail closed. This package is the one
place that knows them all. It decides nothing the packages leave to your application: your identity, principal and
tenant models, your tenant tree, your membership rules, your message senders and every route stay yours.

## Features

- **One install**: every package's configuration, language files and migrations published in a working order, safe to
  run twice, and a list of what remains for your application to bind.
- **Bridging configuration only**: one file for what crosses packages (the shared storage connection, which adapters
  are on, the tenant tree, provisioning, the audit options); each package's own settings stay in its own file.
- **Adapters**: each package's contracts bound to the others' services, every binding a default your application can
  replace through configuration or the container.
- **Fail closed**: an adapter that cannot translate refuses inside the transaction, never by skipping.
- **One transaction**: a change that spans packages commits or rolls back as one on the shared storage connection, with
  a helper that retries the whole of it on a serialisation failure or deadlock.
- **The audit trail**: every package's events mapped to audit entries, and nothing else enforced through events.
- **Partial suites**: a package's features stay off until configured, and a feature that is off binds nothing and checks
  nothing.
- **Ready for production**: safe under Octane and in queue workers, with a combined reset between requests and jobs,
  one call that registers the scheduled work, and a configuration check for a deploy pipeline.

## Installation

```bash
composer require sinemacula/laravel-iam
```

## Quick Start

Publish every package's configuration and migrations, then migrate:

```bash
php artisan iam:install
php artisan migrate
```

The install command says what remains for your application to bind: its senders, its tenant tree and its access
contracts. Then check the whole configuration, for example as a deploy step:

```bash
php artisan iam:check
```

It runs every package's own check and this package's, and exits non-zero on any failure.

## Documentation

The guides live in [docs/guides](docs/guides). The security and lifecycle contracts behind them, for maintainers and
reviewers, are in [docs/design](docs/design/README.md).

## Requirements

- PHP ^8.3 (extensions: bcmath, curl, dom, hash, libxml, mbstring, openssl, zlib)
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer bench              # PHPBench hot-path benchmarks
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
