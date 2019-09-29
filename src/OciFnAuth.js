import jsrsasign from 'jsrsasign';

// Extensions are implemented as JavaScript classes
@registerDynamicValueClass
class OciFnAuth {
	static identifier = "me.harwell.PawExtensions.OciFnAuth";
	static title = "OCI API Auth";
	static inputs = [
		InputField("tenancyId", "Tenancy OCID", "String", { persisted: true, placeholder: "ocid1.tenancy.oc1..aaaaaaaap______keq" }),
		InputField("userId", "Auth User OCID", "String", { persisted: true, placeholder: "ocid1.user.oc1..aaaaaaaas______7ap" }),
		InputField("keyFingerprint", "Public Key Fingerprint", "String", { persisted: true, placeholder: "d1:b2:32:53:d3:5f:cf:68:2d:6f:8b:5f:77:8f:07:" }),
		InputField("privateKey", "Private Key", "SecureValue", { persisted: true })
	];

	evaluate(context) {
		// Ensure that all fields exist
		if (typeof(this.tenancyId) !== "string" || this.tenancyId.length === 0) {
			throw new Error("Tenancy OCID field is empty.");
		}
		if (typeof(this.userId) !== "string" && this.userId.length === 0) {
			throw new Error("User OCID field is empty.");
		}
		if (typeof(this.keyFingerprint) !== "string" && this.keyFingerprint.length === 0) {
			throw new Error("Public key fingerprint field is empty.");
		}
		if (typeof(this.privateKey) !== "string" && this.privateKey.length === 0) {
			throw new Error("Private key field is empty.");
		}

		let dynamicValue = 'Signature version="1"'; // generate some dynamic value
		const request = context.getCurrentRequest();
		const method = request.method;
		let body = request.body;
		let headersToSign = [
			"date",
			"(request-target)",
			"host"
		];

		const methodsThatRequireExtraHeaders = ["POST", "PUT"];
		if (methodsThatRequireExtraHeaders.indexOf(method.toUpperCase()) !== -1) {
			headersToSign = headersToSign.concat([
				"content-length",
				"content-type",
				"x-content-sha256"
			]);
		}

		const urlBase = request.urlBase.replace(/(http|https)\:\/\/([a-zA-Z0-9\.\-_]+)\/.*/gi, "$2");
		const urlPath = request.urlBase.replace(/(http|https)\:\/\/[a-zA-Z0-9\.\-_]+/gi, "");

		// if x-date and date are included, then drop the date header
		if (typeof(request.getHeaderByName("x-date")) === "string") {
			headersToSign[0] = "x-date";
		}

		const apiKeyId = "\"" + this.tenancyId + "/" + this.userId + "/" + this.keyFingerprint + "\"";

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
						signingStr += header + ": " + urlBase;
				break;
				default:
						const val = request.getHeaderByName(header);
						if (typeof(val) === "string") {
							signingStr += header + ": " + val;
						} else {
							throw new Error("Required header has no value: " + header);
						}
				break;
			}

			/*
			if (header == "(request-target)") {
				let requestTarget = "(request-target): " + method.toLowerCase();

				requestTarget += " " + urlBase;

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
			}
			else if (header == "content-length") {
				signingStr += header + ": " + body.length;
			}
			else {
				const val = request.getHeaderByName(header);
				if (typeof(val) === "string") {
					signingStr += header + ": " + val;
				} else {
					throw new Error("Required header has no value: " + header);
				}
			}
			*/
		}

		console.log(signingStr);

		// initialize
		const sig = new jsrsasign.crypto.Signature({ "alg": "SHA256withRSA", "prov": "cryptojs/jsrsa" });
		// initialize for signature validation
		const key = jsrsasign.KEYUTIL.getKey(this.privateKey);
		sig.init(key);
		// update data
		sig.updateString(signingStr);
		// calculate signature
		const sigValueHex = sig.sign();
		//console.log("Sign String: " + signingStr);
		//console.log("Sign Hex: " + sigValueHex);

		// convert signature hex to base64
		const base64Sig = jsrsasign.hextob64(sigValueHex);
		//console.log(sig.state);
		//console.log("Base64 of Hex: " + base64Sig);

		// finish constructing the Authorization header with the signed signature
		dynamicValue += ",headers=" + "\"" + headersToSign.join(" ") + "\"";
		dynamicValue += ",keyId=" + apiKeyId;
		dynamicValue += ",algorithm=\"rsa-sha256\"";
		dynamicValue += ",signature=" + "\"" + base64Sig + "\"";
		//console.log(dynamicValue);

		return dynamicValue;
	}
}
