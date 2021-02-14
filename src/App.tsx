import React, { useState, useEffect } from "react";

import { createVerifierFromJwk } from "./jwt";

export default function App() {
  const [jwt, setJwt] = useState("");
  const [jwk, setJwk] = useState("");
  const [header, setHeader] = useState<any>({});
  const [claim, setClaim] = useState<any>({});
  const [verified, setVerified] = useState(false);

  useEffect(() => {
    const proc = async () => {
      if (!jwt || !jwk) {
        return;
      }

      console.log(jwk);;
      const extractAndVerifyJwt = await createVerifierFromJwk(JSON.parse(jwk));

      try {
        const res = extractAndVerifyJwt(jwt);
        setHeader(res.header);
        setClaim(res.claim);

        const ok = await res.verifyDigitalSign();
        setVerified(ok);
      } catch (e) {
        console.error(e);
      }
    };
    proc();
  }, [jwt, jwk]);

  const handleChangeJwt = (ev: React.ChangeEvent<HTMLTextAreaElement>) => {
    setJwt(ev.target.value);
  };
  const handleChangeJwk = (ev: React.ChangeEvent<HTMLTextAreaElement>) => {
    setJwk(ev.target.value);
  };
  return (
    <div className="grid grid-cols-2 p-5">
      <div>
        <div>Encoded</div>
        <textarea
          className="border-gray-300 border-2 p-2 rounded-lg w-full h-48"
          value={jwt}
          onChange={handleChangeJwt}
        />
        <div>JWK</div>
        <textarea
          className="border-gray-300 border-2 p-2 rounded-lg w-full h-56"
          value={jwk}
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
