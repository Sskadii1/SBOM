# Security Policy

## Reporting Security Issues

If you discover a security issue in this project, please do not open a public issue with sensitive details. Contact the maintainers privately.

## Secrets and Generated Data

This repository must not contain API keys, credentials, `.env` files, generated SBOMs, vulnerability caches, SQLite databases, cloned repositories, LLM outputs, or reachability analysis artifacts.

## Deployment Warning

This project is designed for local research and academic use. Do not expose Streamlit, Neo4j, or related services directly to the Internet without authentication, TLS, network restrictions, and rotated credentials.

## Untrusted Repository Processing

Repositories ingested by this project should be treated as untrusted input. Run analysis in an isolated environment with least-privilege credentials. Dependency installation from cloned repositories is disabled by default and should only be enabled explicitly in disposable research environments.

## External Requests and LLM Use

Optional advisory fetching, GitHub API access, and LLM-assisted analysis may send vulnerability context, repository metadata, or selected code/advisory snippets to external services. Review your `.env` configuration, network policy, and data handling requirements before enabling these features.
