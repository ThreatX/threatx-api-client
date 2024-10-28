# ThreatX API Client
[![Release](https://img.shields.io/github/release/ThreatX/threatx-api-client?label=release)](https://github.com/ThreatX/threatx-api-client/releases)

## Contents
- [Description](#description)
- [Setup](#setup)
- [Usage](#usage)
- [Examples](#examples)

## Description
ThreatX API Client is lightweight Python library designed to streamline the
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
Please check API reference guide and source code for available methods and commands.

## Examples
### **Class initialization**
```python
tx_api = Client("prod", "apikeytest1234")
```

### **Single request**
```python
tx_api.method([
    {
        "command": "get",
        "customer_name": "random_test_tenant",
        "name": "randomsite1.com"
    }
])
```
For a single requests the [] list brackets can be omitted in payload.  
The response will always be as it is, not in the list, but a plain dictionary.

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
The response will be the list of dicts, each dict represents a single response.

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
Marker variable will be returned with each request which it was attached to as a key and the response as its value. It could be useful for a further filtering/processing steps.

#### Output example:
```
[
{'randomsite1.com': {'hash': 1000000000001, 'hostname': 'randomsite1.com', ...}},
{'randomsite2.com': {'hash': 1000000000002, 'hostname': 'randomsite2.com', ...}},
{'randomsite3.com': {'hash': 1000000000003, 'hostname': 'randomsite3.com', ...}}
]
```
