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

export const createCryptoKeyFromJwk = (jwk: any) => {
  const shaSize = jwk.alg.replace(/S(\d+)$/, "$1");
  switch (jwk.kty.toUpperCase()) {
    case "EC": {
      return crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "ECDSA",
          namedCurve: jwk.crv,
          hash: {
            name: `SHA-${shaSize}`,
          },
        },
        false,
        ["verify"]
      );
    }
  }
  throw new Error(`unknown kty ${JSON.stringify(jwk)}`);
};

const ALGORITHMS = {
  ES256: {
    name: "ECDSA",
    hash: { name: "SHA-256" },
  },
  ES512: {
    name: "ECDSA",
    hash: { name: "SHA-512" },
  },
} as const;

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
  if (!jwk.alg || !Object.keys(ALGORITHMS).includes(jwk.alg)) {
    throw new Error(`unknown algorithm: ${jwk.alg}`);
  }
  const algorithmParam = ALGORITHMS[jwk.alg as keyof typeof ALGORITHMS];
  return (jwt: string) => {
    const { header, claim, payload, signature } = extract(jwt);
    return {
      header,
      claim,
      verifyDigitalSign: () =>
        verifyDigitalSign(algorithmParam, payload, signature, publicKey),
    };
  };
};
