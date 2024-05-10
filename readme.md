# 2014 ETH Wallet AES Key Checker

## Description
This script is designed to decrypt a given hexadecimal encrypted seed using AES 128 CBC encryption, and then generate an Ethereum private key and its corresponding public Ethereum address. The script will also validate if the generated Ethereum address matches a given expected address.

## Dependencies
- **Python 3.6+**: The primary programming language used.
- **PyCryptodome**: A self-contained cryptographic library for Python.
- **eth-keys**: A utility library for working with Ethereum keys.

## Installation
To run this script, you need to install Python and the required Python packages. You can install the required packages using pip. If you don't have pip installed, you can install it by following [this guide](https://pip.pypa.io/en/stable/installation/).

### Installing Python Packages
```bash
pip install pycryptodome eth-keys

## Running the script
```bash
python aes_key_evaluator.py

