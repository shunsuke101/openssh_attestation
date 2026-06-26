# openssh_attestation

This repository provides an extension to **OpenSSH Portable** that integrates TPM-based key attestation. 
It allows you to embed TPM quotes, signatures, and nonces directly into OpenSSH certificates as custom extensions, and automatically decode (base64)/extract them during certificate inspection.

## Installation & Build Instructions

To use this extension, you need to copy the modified source files into the official `openssh-portable` repository and build it from source.

### 1. Prerequisites
Make sure you have cloned the official OpenSSH Portable repository:
```bash
git clone https://github.com/openssh/openssh-portable.git
cd openssh-portable
sudo apt update
sudo apt install [need package]
autoconf
./config
make && make test
```

### 2. Apply the Attestation Files
# Example command (adjust paths as necessary)
cp path/to/openssh_attestation/ssh-keygen.c /path/to/openssh-portable/ssh-keygen.c
cd openssh-portable
make

### Usage
Inspecting Certificates & Automatic File Extraction
When you verify or inspect a user certificate using the newly built ssh-keygen, the embedded TPM attestation data (Base64-encoded) will be automatically parsed, decoded back into raw binary format, and saved to your local directory for validation.

Run the following command:
./ssh-keygen -Lf ~/.ssh/test_cert-cert.pub

