# OciApiAuth

[![CodeQL](https://github.com/scottharwell/OciFnAuth/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/scottharwell/OciFnAuth/actions/workflows/codeql-analysis.yml)

This extension creates the `Authorization` header for requests to Oracle's OCI REST APIs.  The extension will leverage the required headers based on the type of request (GET, POST, etc.).  See the OCI [signing requests](https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm) documentation for reference regarding the required headers.  

This extension requires that you use an OCI account that has permissions to access the OCI REST APIs and that you have configured a public/private key pair for your account.

## Example

The following is a list of headers used to generate the signing string based on the HTTP method that is used.

* `Host`: Provided by Paw. You do not need to manually set this value.
* `Date`: Use the `{Timestamp}` dynamic value built into Paw to create an RFC 1123/2822 value for the current time. *`x-date` may be used as an alternative for `Date`*.
* `Content-Length`: Provided by Paw. You do not need to manually set this value. 
* `Content-Type`: `application/json`
* `Accept`: `application/json`
* `x-content-sha256`: Use the `SHA256` dynamic value with base64 encoding as the value for this header.  In the input for the `SHA256` dynamic value, set the input to another dynamic value `Request Raw Body`.  These native dynamic values will generate the proper hash for this header.
* `Authorization`: Use this extension!

Example `GET` request configuration:

* `Date`: Use the `{Timestamp}` dynamic value to create an RFC 1123/2822 value for the current time.
* `Accept`: `application/json`
* `Authorization`: `{OCI API Auth}` Use this extension!

![Header Configuration](https://raw.githubusercontent.com/scottharwell/OciFnAuth/main/img/get_headers.png)

Example `POST` request configuration:

* `Date`: Use the `{Timestamp}` dynamic value to create an RFC 1123/2822 value for the current time.
* `x-content-sha256`:  Use the `{SHA256}` dynamic value with base64 encoding as the value for this header.
* `Authorization`: `{OCI API Auth}` Use this extension!

![Header Configuration](https://raw.githubusercontent.com/scottharwell/OciFnAuth/main/img/post_headers.png)

The configuration of the `{SHA256}` dynamic value:

![SHA265 Header](https://raw.githubusercontent.com/scottharwell/OciFnAuth/main/img/sha256_header.png)

## Configuring the Extension

The input fields of this extension requires the private key that matches your public key fingerprint in order to sign the request so that OCI will consume it. This is the same mechanism used in the `oci_curl.sh` documentation, but with the key being read from Paw rather than your local file system.  This approach is required due to app sand-boxing in MacOS apps.

![Extension Input Fields](https://raw.githubusercontent.com/scottharwell/OciFnAuth/main/img/ext_config.png)

Because of the private key use, you should enable encryption in your Paw project so that the key remains secure. It is recommended that you have multiple keys and that you only use a key for testing with the Paw client. The `Private Key` field will be green if you have encryption enabled.

## Development

### Prerequisites

```shell
npm install
```

### Build

```shell
npm run build
```

### Install

```shell
make install
```

### Test

```shell
npm test
```

## License

This Paw Extension is released under the [MIT License](./LICENSE). Feel free to fork, and modify!

Copyright © 2020 Scott Harwell