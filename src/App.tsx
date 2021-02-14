import React, { useState, useEffect } from "react";

import { createFromJwk, createHmac } from "./jwt";

export default function App() {
  const [jwt, setJwt] = useState("");
  const [key, setKey] = useState("");
  const [header, setHeader] = useState<any>({});
  const [claim, setClaim] = useState<any>({});
  const [verified, setVerified] = useState(false);
  const [isHmac, setIsHmac] = useState(false);

  useEffect(() => {
    const proc = async () => {
      if (!jwt || !key) {
        return;
      }

      console.log(jwt, key);
      try {
        if (isHmac) {
          const extractAndVerifyJwt = await createHmac(key);
          const res = extractAndVerifyJwt(jwt);
          setHeader(res.header);
          setClaim(res.claim);

          const ok = await res.verifyDigitalSign();
          setVerified(ok);
          console.log(29);;
        } else {
          const extractAndVerifyJwt = await createFromJwk(JSON.parse(key));

          const res = extractAndVerifyJwt(jwt);
          setHeader(res.header);
          setClaim(res.claim);

          const ok = await res.verifyDigitalSign();
          setVerified(ok);
        }
      } catch (e) {
        console.error(e);
      }
    };
    proc();
  }, [jwt, key, isHmac]);

  const handleChangeJwt = (ev: React.ChangeEvent<HTMLTextAreaElement>) => {
    setJwt(ev.target.value);
  };
  const handleChangeJwk = (ev: React.ChangeEvent<HTMLTextAreaElement>) => {
    setKey(ev.target.value);
  };
  return (
    <div className="grid grid-cols-2 p-5">
      <div>
        <div>
          <input
            type="checkbox"
            id="hmac"
            checked={isHmac}
            onChange={() => setIsHmac((prev) => !prev)}
          />
          <label htmlFor="hmac">HMAC</label>
        </div>
        <div>Encoded</div>
        <textarea
          className="border-gray-300 border-2 p-2 rounded-lg w-full h-48"
          value={jwt}
          onChange={handleChangeJwt}
        />
        <div>{isHmac ? "secret" : "JWK"}</div>
        <textarea
          className="border-gray-300 border-2 p-2 rounded-lg w-full h-56"
          value={key}
          onChange={handleChangeJwk}
        />
      </div>
      <div className="px-5">
        <div>Decoded</div>
        <div>HEADER</div>
        <code>
          <pre>{JSON.stringify(header, null, "  ")}</pre>
        </code>
        <div>PAYLOAD</div>
        <code>
          <pre>{JSON.stringify(claim, null, "  ")}</pre>
        </code>
        <div>Verified</div>
        <div>{verified.toString()}</div>
      </div>
    </div>
  );
}
