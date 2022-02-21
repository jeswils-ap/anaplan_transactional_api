# anaplan-api

Anaplan-Transact-API is a Python library wrapper for [Anaplan Transactional API](https://anaplanbulkapi20.docs.apiary.io/) and [Anaplan Authentication API](https://anaplanauthentication.docs.apiary.io/).

## Installation

Use the package manager [pip](https://pypi.org/project/anaplan-transact-api/) to install Anaplan-Transact-API.

```bash
pip3 install anaplan_transact_api
```

## Usage

```python
import logging
from anaplan_transactional_api import anaplan

```

## Known Issues
This library currently uses PyJKS library for handling Java Keystore files. This project does not appear to be actively developed, and there is a known error installing pycryptodomex and twofish - both dependencies for PyJKS. The core files required from this library are:

- jks.py
- rfc2898.py
- sun_crypto.py
- util.py

### PyJKS Requirements
- javaobj-py3
- pyasn1
- pyasn1_modules

You can simply download, remove the unnecessary files, and drop the jks folder in your site-package directory to work around the error.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[BSD](https://opensource.org/licenses/BSD-2-Clause)