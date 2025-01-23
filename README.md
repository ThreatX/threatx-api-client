# ThreatX API Client

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Actions status](https://github.com/astral-sh/ruff/workflows/CI/badge.svg)](https://github.com/ThreatX/threatx-api-client/actions)
[![Release](https://img.shields.io/github/release/ThreatX/threatx-api-client?label=release)](https://github.com/ThreatX/threatx-api-client/releases)
![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2FThreatX%2Fthreatx-api-client%2Frefs%2Fheads%2Fmain%2Fpyproject.toml)

## Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing & Support](#contributing--support)
- [License](#license)

## Description

Python aiohttp based ThreatX API Client is lightweight Python library designed to streamline the
interaction with ThreatX API.

## Features

- Async backend
- Command validation
- Error handling
- Response marking
- Token auto renewal

## Installation

ThreatX API Client supports multiple installation methods.
See [documentation](https://github.com/ThreatX/threatx-api-client/docs/installation.md) for available options.

## Usage

### Class import

1. Import class `Client`: `from threatx_api_client import Client`
2. Initialize class object with required environment and API key provided: `tx_api = Client(api_env, api_key)`

#### Available environment options:

- `prod`
- `pod`

### API methods and commands

Please check API reference guide and the source code for available methods and commands.

#### Examples

Code examples are available here: https://github.com/ThreatX/threatx-api-client/examples

## Contributing & Support

Feel free to open an [issue](https://github.com/ThreatX/threatx-api-client/issues) or
a [pull request](https://github.com/ThreatX/threatx-api-client/pulls) if you find a bug or want to suggest a new
feature.
For more information, check out
our [contributing guide](https://github.com/ThreatX/threatx-api-client/CONTRIBUTING.md).
For general support, please reach out to our support team: [support@threatx.com](mailto:support@threatx.com).

## License

Copyright © 2023-2025 ThreatX, https://www.threatx.com/

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
