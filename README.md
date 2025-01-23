# ThreatX API Client

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Actions status](https://github.com/astral-sh/ruff/workflows/CI/badge.svg)](https://github.com/ThreatX/threatx-api-client/actions)


## Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing & Support](#contributing--support)
- [License](#license)

## Description

Python aiohttp based ThreatX API Client is lightweight Python library designed to streamline the interaction with ThreatX API.

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

## Setup

#### Install with pip:

- Latest: `pip install git+https://github.com/ThreatX/threatx-api-client.git`
- Release: `pip install https://github.com/ThreatX/threatx-api-client/releases/download/v1.6.1/threatx_api_client-1.6.1-py3-none-any.whl`

#### Install with Poetry

1. Install compatible Python version: >=3.8 <3.13
2. `git pull git@github.com:ThreatX/threatx-api-client.git`
3. `poetry install`
4. Import library to where you want

## Usage

### Initial setup

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

Please check API reference guide and source code for available methods and commands.

## Examples

### **Class initialization**

```python
tx_api = Client("prod", "apikeytest1234")
```

### **Single request**

```python
tx_api.method(
    {
        "command": "get",
        "customer_name": "random_test_tenant",
        "name": "randomsite1.com"
    }
)
```

For a single request, the list brackets should be omitted in payload.
The response type depends on the input type used and the API response type.

#### Output example:

```
{'hash': 1000000000001, 'hostname': 'randomsite1.com', ... }
```

### **Multiple requests**

```python
sites = ["randomsite1.com", "randomsite2.com", "randomsite3.com"]
tx_api.method([
    {
        "command": "get",
        "customer_name": "random_test_tenant",
        "name": site
    } for site in sites
])
```

Use list of dicts to send a batch of payloads and process them asynchronously.  
The response will be the list of data entries.

#### Output example:

```
[
{'hash': 1000000000001, 'hostname': 'randomsite1.com', ...,}
{'hash': 1000000000002, 'hostname': 'randomsite2.com', ...},
{'hash': 1000000000003, 'hostname': 'randomsite3.com', ...}
]
```

### **Multiple marked requests**

```python
sites = ["randomsite1.com", "randomsite2.com", "randomsite3.com"]
tx_api.method([
    {
        "command": "get",
        "customer_name": "random_test_tenant",
        "name": site,
        "marker_var": site
    } for site in sites
])
```

The same as "Multiple requests" but with "marker_var" entry added to each request.  
Marker variable will be returned with each request which it was attached to as a key and the response as its value. It
could be useful for a further filtering/processing steps.

#### Output example:

```
[
{'randomsite1.com': {'hash': 1000000000001, 'hostname': 'randomsite1.com', ...}},
{'randomsite2.com': {'hash': 1000000000002, 'hostname': 'randomsite2.com', ...}},
{'randomsite3.com': {'hash': 1000000000003, 'hostname': 'randomsite3.com', ...}}
]
```
