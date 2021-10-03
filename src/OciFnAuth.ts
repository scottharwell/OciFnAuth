import jsrsasign from 'jsrsasign';

// Extensions are implemented as JavaScript classes
// @ts-ignore
@registerDynamicValueClass
class OciFnAuth {
	static identifier = "me.harwell.PawExtensions.OciFnAuth";
	static title = "OCI API Auth";
	static inputs = [
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

	static methodsThatRequireExtraHeaders = ["POST", "PUT", "PATCH"];

	version: string | undefined;
	tenancyId: string | undefined;
	userId: string | undefined;
	keyFingerprint: string | undefined;
	privateKey: string | undefined;

	evaluate(context: any) {
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

		if (OciFnAuth.methodsThatRequireExtraHeaders.includes(method.toUpperCase())) {
			headersToSign = headersToSign.concat([
				"content-length",
				"content-type",
				"x-content-sha256"
			]);
		}

		// if x-date and date are included, then drop the date header
		if (typeof (request.getHeaderByName("x-date")) === "string") {
			headersToSign[ 0 ] = "x-date";
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
					} else {
						throw new Error("Required header has no value: " + header);
					}
					break;
			}
		}

		// initialize
		const sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
		// initialize for signature validation
		const key = jsrsasign.KEYUTIL.getKey(this.privateKey);
		sig.init(key);
		// update data
		sig.updateString(signingStr);
		// calculate signature
		const sigValueHex = sig.sign();

		// convert signature hex to base64
		const base64Sig = jsrsasign.hextob64(sigValueHex);
		const headersStr = headersToSign.join(" ");

		// finish constructing the Authorization header with the signed signature
		const dynamicValue = `Signature version="${this.version}",headers="${headersStr}",keyId="${apiKeyId}",algorithm="rsa-sha256",signature="${base64Sig}"`;

		return dynamicValue;
	}

	validateHeaders(context: any) {
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

		if (OciFnAuth.methodsThatRequireExtraHeaders.includes(method.toUpperCase())) {
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
}
