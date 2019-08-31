# OciFnAuth

This extention creates the `authorization` header for a direct HTTP REST request to Oracle's OCI implementation of the F(n) platform.  The extension will leverage the required headers based on the type of request (GET, POST, etc.).  See the OCI F(n) documentation for reference regarding the required headers.  

POST and PUT requests also require a `x-content-sha256` header calculated based on the body of the request.  The default `SHA256` dynamic value should be used to calculate this header; ensure that base64 encoding is used.

## Example

The following image shows all of the headers required for a `POST` request.

* Host: Provided by OCI. This example uses an environment variable to store this value.
* Date: Use the {Timestamp} dynamic value built into Paw to create an RFC 1123/2822 value for the current time.
* Content-Length: Use the {Request Body Length} dynamic value built into Paw to calculate this value.  Paw may complain that the value creates a self-dependency, but it still works. 
* Content-Type: `application/json`
* x-content-sha256: Use the `SHA256` dynamic value with base64 encoding.
* Authorization: Use this extension.

![Header Configuration](https://i.imgur.com/TIMng7P.png)

## Configuring the Extension

The input fields of this extension requires your OCI private key in order to sign the request so that OCI will consume it. This is the same mechanism used in the `oci_curl.sh` documentation, but with the key being read from Paw rather than your local file system.  This approach is required due to app sandboxing in MacOS apps.

![Extension Input Fields](https://i.imgur.com/3Npipux.png)

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

Copyright © 2019 Scott Harwell