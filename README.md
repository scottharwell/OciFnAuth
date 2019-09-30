# OciApiAuth

This extention creates the `authorization` header for request to Oracle's OCI REST APIs.  The extension will leverage the required headers based on the type of request (GET, POST, etc.).  See the OCI REST authorization documentation for reference regarding the required headers.  

POST and PUT requests also require a `x-content-sha256` header calculated based on the body of the request.  The default `SHA256` dynamic value should be used to calculate this header; ensure that base64 encoding is used.

## Example

The following image shows all of the headers required for a `POST` request.

* Host: Provided as part of the request. You do not need to manually set this value.
* Date: Use the {Timestamp} dynamic value built into Paw to create an RFC 1123/2822 value for the current time.
* Content-Length: Provided by Paw. You do not need to manually set this value. 
* Content-Type: `application/json`
* x-content-sha256: Use the `SHA256` dynamic value with base64 encoding as the value for this header.  In the input for the `SHA256` dynamic value, set the input to another dynamic value `Request Raw Body`.  These native dynamic values will generate the proper hash for this header.
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