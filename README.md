# ssh-cert-info

[![CI](https://github.com/fcuny/ssh-cert-info/actions/workflows/ci.yml/badge.svg)](https://github.com/fcuny/ssh-cert-info/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/fcuny/ssh-cert-info)](https://go.dev/)

A command-line tool that scans your `~/.ssh` directory for SSH certificates and displays their details, including type, key ID, validity period, principals, and expiration status.

## Installation

```
go install fcuny.net/ssh-cert-info@latest
```

## Usage

```
ssh-cert-info
```
