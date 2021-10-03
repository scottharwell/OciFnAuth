"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var OciFnAuth_1;
Object.defineProperty(exports, "__esModule", { value: true });
const jsrsasign_1 = __importDefault(require("jsrsasign"));
// Extensions are implemented as JavaScript classes
// @ts-ignore
let OciFnAuth = OciFnAuth_1 = class OciFnAuth {
    evaluate(context) {
        // Ensure that all fields exist
        if (typeof (this.version) !== "string" || this.version.length === 0) {
            throw new Error("Signature version was not selected.");
        }
        if (typeof (this.tenancyId) !== "string" || this.tenancyId.length === 0) {
            throw new Error("Tenancy OCID field is empty.");
        }
        if (typeof (this.userId) !== "string" || this.userId.length === 0) {
            throw new Error("User OCID field is empty.");
        }
        if (typeof (this.keyFingerprint) !== "string" || this.keyFingerprint.length === 0) {
            throw new Error("Public key fingerprint field is empty.");
        }
        if (typeof (this.privateKey) !== "string" || this.privateKey.length === 0) {
            throw new Error("Private key field is empty.");
        }
        // Ensure that required headers are set. If not, then generate them.
        // The Paw API doesn't support creating values dynamically from within other dynamic value extensions.
        // If this is ever supported, then this extension can auto-generate dependent headers.
        this.validateHeaders(context);
        const request = context.getCurrentRequest();
        const method = request.method;
        let body = request.body;
        request.setHeader("accept", "application/json");
        let headersToSign = [
            "date",
            "(request-target)",
            "host"
        ];
        if (OciFnAuth_1.methodsThatRequireExtraHeaders.includes(method.toUpperCase())) {
            headersToSign = headersToSign.concat([
                "content-length",
                "content-type",
                "x-content-sha256"
            ]);
        }
        // if x-date and date are included, then drop the date header
        if (typeof (request.getHeaderByName("x-date")) === "string") {
            headersToSign[0] = "x-date";
        }
        const hostname = request.urlBase.replace(/(http|https)\:\/\/([a-zA-Z0-9\.\-_]+)\/.*/gi, "$2");
        const urlPath = request.urlBase.replace(/(http|https)\:\/\/[a-zA-Z0-9\.\-_]+/gi, "");
        const apiKeyId = `${this.tenancyId}/${this.userId}/${this.keyFingerprint}`;
        let signingStr = "";
        for (const header of headersToSign) {
            if (signingStr.length > 0) {
                signingStr += "\n";
            }
            switch (header) {
                case "(request-target)":
                    let requestTarget = "(request-target): " + method.toLowerCase() + " " + urlPath;
                    const paramNames = request.getUrlParametersNames();
                    if (paramNames !== undefined && paramNames.length > 0) {
                        let queryStr = "?";
                        let index = 0;
                        for (const param of paramNames) {
                            const val = encodeURIComponent(request.getUrlParameterByName(param));
                            queryStr += index > 0 ? "&" : "";
                            queryStr += param + "=" + val;
                            index++;
                        }
                        requestTarget += queryStr;
                    }
                    signingStr += requestTarget;
                    break;
                case "content-length":
                    signingStr += header + ": " + body.length;
                    break;
                case "host":
                    signingStr += header + ": " + hostname;
                    break;
                default:
                    const val = request.getHeaderByName(header);
                    if (typeof (val) === "string") {
                        signingStr += header + ": " + val;
                    }
                    else {
                        throw new Error("Required header has no value: " + header);
                    }
                    break;
            }
        }
        // initialize
        const sig = new jsrsasign_1.default.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
        // initialize for signature validation
        const key = jsrsasign_1.default.KEYUTIL.getKey(this.privateKey);
        sig.init(key);
        // update data
        sig.updateString(signingStr);
        // calculate signature
        const sigValueHex = sig.sign();
        // convert signature hex to base64
        const base64Sig = jsrsasign_1.default.hextob64(sigValueHex);
        const headersStr = headersToSign.join(" ");
        // finish constructing the Authorization header with the signed signature
        const dynamicValue = `Signature version="${this.version}",headers="${headersStr}",keyId="${apiKeyId}",algorithm="rsa-sha256",signature="${base64Sig}"`;
        return dynamicValue;
    }
    validateHeaders(context) {
        const request = context.getCurrentRequest();
        const method = request.method;
        const acceptHeader = request.getHeaderByName("accept");
        const xDate = request.getHeaderByName("x-date");
        if (!acceptHeader) {
            console.log("accept header not set. Adding value.");
            request.setHeader("accept", "application/json");
        }
        if (!xDate) {
            console.log("x-date header not set. Adding value.");
            // @ts-ignore
            var dynamicTimeValue = DynamicValue('com.luckymarmot.TimestampDynamicValue', {
                now: true,
                format: 2
            });
            console.log(dynamicTimeValue);
            request.setHeader("x-date", dynamicTimeValue);
        }
        if (OciFnAuth_1.methodsThatRequireExtraHeaders.includes(method.toUpperCase())) {
            const contentHash = request.getHeaderByName("x-content-sha256");
            if (!contentHash) {
                console.log("x-content-sha256 header not set. Adding value.");
                // @ts-ignore
                var rawBodyDynamicValue = DynamicValue('com.luckymarmot.RequestRawBodyDynamicValue');
                // @ts-ignore
                var hashDynamicValue = DynamicValue('com.luckymarmot.HashDynamicValue', {
                    input: rawBodyDynamicValue,
                    hashType: 5,
                    encoding: 1
                });
                console.log(hashDynamicValue);
                request.setHeader("x-content-sha256", hashDynamicValue);
            }
        }
    }
};
OciFnAuth.identifier = "me.harwell.PawExtensions.OciFnAuth";
OciFnAuth.title = "OCI API Auth";
OciFnAuth.inputs = [
    // At this point, there is only one signing version. This select box will help manage future releases.
    // @ts-ignore
    InputField("version", "Signature Version", "Select", { "choices": { "1": "1" }, persisted: true }),
    // @ts-ignore
    InputField("tenancyId", "Tenancy OCID", "String", { persisted: true, placeholder: "ocid1.tenancy.oc1..aaaaaaaap______keq" }),
    // @ts-ignore
    InputField("userId", "Auth User OCID", "String", { persisted: true, placeholder: "ocid1.user.oc1..aaaaaaaas______7ap" }),
    // @ts-ignore
    InputField("keyFingerprint", "Public Key Fingerprint", "String", { persisted: true, placeholder: "d1:b2:32:53:d3:5f:cf:68:2d:6f:8b:5f:77:8f:07:" }),
    // @ts-ignore
    InputField("privateKey", "Private Key", "SecureValue", { persisted: true })
];
OciFnAuth.methodsThatRequireExtraHeaders = ["POST", "PUT", "PATCH"];
OciFnAuth = OciFnAuth_1 = __decorate([
    registerDynamicValueClass
], OciFnAuth);
