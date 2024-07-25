# ThreatX API Client
[![Release](https://img.shields.io/github/release/ThreatX/threatx-api-client?label=release)](https://github.com/ThreatX/threatx-api-client/releases)

## Contents
- [Description](#description)
- [Setup](#setup)
- [Usage](#usage)

## Description
ThreatX API Client is lightweight Python library designed to streamline the
interaction with ThreatX API.

## Setup
#### Install with pip:
- Latest: `pip install git+https://github.com/ThreatX/threatx-api-client.git`
- Release: `pip install https://github.com/ThreatX/threatx-api-client/releases/download/v1.3.0/threatx_api_client-1.3.0-py3-none-any.whl`

#### Install with Poetry
1. Install compatible Python version: >=3.8 <3.13
2. `git pull git@github.com:ThreatX/threatx-api-client.git`
3. `poetry install`
4. Import library to where you want

## Usage
### Initial setup
1. Import class `Client`: `from threatx_api_client import Client`
2. Initialize class object with required environment and API key provided: `tx_api = Client(api_env, api_key)`

Available environments:
- `prod`
- `pod`

### API methods and commands
Please check API reference guide and source code for available methods and commands.

#### Example
```
tx_api = Client("prod", "apikeytest1234")
payloads = [
    {
        "command": "list",
        "customer_name": "testing_tenant"
    }
]
response = tx_api.sites(payloads)
print(response)
```
