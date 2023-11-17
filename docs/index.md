# Welcome to The ThreatX Python API Client Library

This library is for ThreatX customers who wish manage their account resources programmatically using Python.  




## Quick Start

__Requires *Python 3.10+*__  

It is recommended that you use Poetry to manage your project's dependencies, including `threatx_api_client`.

```bash
# Add to the project
poetry add https://github.com/ThreatX/threatx-api-client
poetry install
```

It is, however, optional, and so if you don't wish to use Poetry, you can still simply use pip:

    pip install https://github.com/ThreatX/threatx-api-client


---

## Example Usage

There are __two (2)__ parameters needed in order to successfully
instantiate an instance of the client and authenticate with ThreatX:  
__1.)__ The name of the environment, or zone, you are targetting (e.g., `tx-production`, `dev`) and 
__2.)__ a valid ThreatX API key

```python
""" 
my_txapp/app.py
"""

import os
from threatx_api_client import Client

TXZONE = os.environ.get('TX_ZONE', default='tx-production')
TXKEY = os.environ.get('TX_API_KEY', default=None)

# Create a new client and authenticate with ThreatX services
client = Client(TXZONE, TXKEY)

# Example Call to get a list of users
users = client.users({'command': 'list'})

```

--- 

## New Poetry Users

If you are not familiar with Poetry, here are the basic steps to getting it setup and 
a nrew project for your application created.

### Initialize a Poetry Project

```bash
export PATH="${HOME}/.local/bin:${HOME}"


# Install Poetry if needed
python3 -m pip install --upgrade pip
python3 -m pip install poetry

# Create a new source directory for your new project
mkdir -p ~/src/my-txapp && cd ~/src/my-txapp

# Answer the prompts following the `poetry init` command to initialize your project
poetry init

# Create virtualenvs automatically
poetry config --local virtualenvs.create true
# Respect Pyenv and .python-version
poetry config --local virtualenvs.prefer-active-python true 
# (OPTIONAL) Install to .venv in the project. 
poetry config --local virtualenvs.in-project true 

# Anser the prompts to complete your project's creation
poetry env use python3
```

--- 

## Development

This section is for contributors of the _threatx-api-client_ project.

### Building the Project 

Several build targets exist to aid in building and deploying the project 
and its automatically generated documentation.

```bash
# See all automation targets
make help
```

#### Documentation

Some part of the documentation are generated into a static site from the source code and other
parts are hand-written. 

```bash
# Build the documentation at site/
make -C docs build

# Serve the documentation with live-reload at http://localhost:8000
make -C docs serve

# Deploy the documentation to Github Pages
make -C docs deploy
```
 
##### Customize The Documentation
 
 Edit the stylesheets at `docs/style.css` in order to customize the theme. 



