const decodeBase64Url = (text: string) => {
  return atob(text.replace(/-/g, "+").replace(/_/g, "/"));
};

const toArrayBuffer = (text: string) => {
  const buf = new ArrayBuffer(text.length);
  const bufUint8 = new Uint8Array(buf);
  for (let i = 0; i < text.length; i++) {
    bufUint8[i] = text.charCodeAt(i);
  }
  return buf;
};

export const extract = (jwt: string) => {
  const [headerEncoded, claimEncoded, signatureEncoded] = jwt.split(".");
  const signature = toArrayBuffer(decodeBase64Url(signatureEncoded));
  const payload = toArrayBuffer(`${headerEncoded}.${claimEncoded}`);
  const header = JSON.parse(decodeBase64Url(headerEncoded));
  const claim = JSON.parse(decodeBase64Url(claimEncoded));

  return {
    /** JWTから取得した header */
    header,
    /** JWTから取得した claim */
    claim,
    /** JWS検証対象のペイロード */
    payload,
    /** JWS検証用の電子署名 */
    signature,
  };
};

/*
const createCryptoKeyFromPem = (armored: string) => {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = armored.substring(
    pemHeader.length,
    armored.length - pemFooter.length
  );

  const binary = atob(
    // armored
    //   .trim()
    //   .replace(/^-----BEGIN [A-Z]+ KEY-----/, "")
    //   .replace(/^-----END [A-Z]+ KEY$/, "")
    pemContents
  );
  return crypto.subtle.importKey(
    "spki",
    toArrayBuffer(binary),
    {
      name: "ECDSA",
      namedCurve: "P-256",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  );
};
*/

export const createCryptoKeyFromJwk = (jwk: any) => {
  // switch (jwk.kty) {
  // case "ec": {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "ECDSA",
      namedCurve: jwk.crv,
      hash: {
        name: "SHA-256",
      },
    },
    false,
    ["verify"]
  );
  // }
  // }
};

// const Algorithms = {
//   ES256: {
//     name: "ECDSA",
//     hash: { name: "SHA-256" },
//   },
//   ES512: {
//     name: "ECDSA",
//     hash: { name: "SHA-512" },
//   },
// } as const;

export const verifyDigitalSign = async (
  algorithmParam: EcdsaParams | RsaPssParams,
  payload: ArrayBuffer,
  signature: ArrayBuffer,
  publicKey: CryptoKey
): Promise<boolean> => {
  return crypto.subtle.verify(algorithmParam, publicKey, signature, payload);
};

export const createVerifierFromJwk = async (jwk: JsonWebKey) => {
  const publicKey = await createCryptoKeyFromJwk(jwk);
  return (jwt: string) => {
    const algorithmParam = {
      name: "ECDSA",
      hash: {
        name: "SHA-256",
      },
    };
    const { header, claim, payload, signature } = extract(jwt);
    return {
      header,
      claim,
      verifyDigitalSign: () =>
        verifyDigitalSign(algorithmParam, payload, signature, publicKey),
    };
  };
};
