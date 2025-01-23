# ThreatX API Client
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![Release](https://img.shields.io/github/release/ThreatX/threatx-api-client?label=release)](https://github.com/ThreatX/threatx-api-client/releases)
![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2FThreatX%2Fthreatx-api-client%2Frefs%2Fheads%2Fmain%2Fpyproject.toml)

## Contents
- [Description](#description)
- [Setup](#setup)
- [Usage](#usage)
- [Examples](#examples)

## Description
Python aiohttp based ThreatX API Client is lightweight Python library designed to streamline the
interaction with ThreatX API.

## Features
- Async backend
- Command validation
- Error handling
- Response marking
- Token auto renewal

## Setup
#### Install with pip:
- Latest: `pip install git+https://github.com/ThreatX/threatx-api-client.git`
- Release: `pip install https://github.com/ThreatX/threatx-api-client/releases/download/v1.6.0/threatx_api_client-1.5.0-py3-none-any.whl`

#### Install with Poetry
1. Install compatible Python version: >=3.8 <3.13
2. `git pull git@github.com:ThreatX/threatx-api-client.git`
3. `poetry install`
4. Import library to where you want

## Usage
### Initial setup
1. Import class `Client`: `from threatx_api_client import Client`
2. Initialize class object with required environment and API key provided: `tx_api = Client(api_env, api_key)`

#### Available environments:
- `prod`
- `pod`

### API methods and commands
Please check API reference guide and the source code for available methods and commands.

## Examples
Code examples are available here: https://github.com/ThreatX/threatx-api-client/examples 