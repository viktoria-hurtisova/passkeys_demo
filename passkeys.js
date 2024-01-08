const users = [];
const RP_ID = "lioness-sacred-akita.ngrok-free.app";

//this function decode Base64url string into Uint8Array
// from https://stackoverflow.com/questions/70652829/decode-base64url-as-uint8array
function decode(encoded) {
  let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  return new Uint8Array(
    atob(base64)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
}

//encode Uint8Array into Base64url string
// from https://gist.github.com/themikefuller/c1de46cbbdad02645b9dc006baedf88e
function encode(input) {
  return btoa(
    Array.from(input)
      .map((val) => {
        return String.fromCharCode(val);
      })
      .join("")
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/\=/g, "");
}

function parseClientDataJSON(input) {
  const utf8Decoder = new TextDecoder("utf-8");
  const decodedClientData = utf8Decoder.decode(input);
  return JSON.parse(decodedClientData);
}

function validateClientData(clientData, challenge, expectedType) {
  if (clientData.type !== expectedType) {
    throw "The credentials.response.clientDataJSON.type has invalid value.";
  }
  if (clientData.challenge !== encode(challenge)) {
    throw "The credentials.response.clientDataJSON.challenge does not equal the base64url encoding of options.challenge.";
  }
  if (window.location.origin !== clientData.origin) {
    throw "The credentials.response.clientDataJSON.origin has invalid value.";
  }

  return true;
}

function getCredentials(userName) {
  return users
    .filter((user) => user.userName === userName)
    .map((user) => ({ type: "public-key", id: user.rawId }));
}

function checkCredentialId(id) {
  let result = users.filter((user) => user.publicKeyObject.credentialId === id);
  if (result.length > 0) {
    throw "User with this credentialId already exists.";
  }
}

async function getCreateOptions(userName) {
  let challenge = window.crypto.getRandomValues(new Uint8Array(32));
  let randomId = window.crypto.getRandomValues(new Uint8Array(32));
  let excludeCredentials = getCredentials(userName);
  const PublicKeyCredentialCreateOptions = {
    challenge: challenge, //should be at least 16 bytes
    rp: {
      name: "Security for SW Systems in practice",
      id: RP_ID,
    },
    user: {
      id: randomId,
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7, // "ES256" as registered in the IANA COSE Algorithms registry
      },
      {
        type: "public-key",
        alg: -257, // Value registered by this specification for "RS256"
      },
    ],
    excludeCredentials: excludeCredentials,
    //authenticatorSelection: {
    //    authenticatorAttachment: "cross-platform",
    //},
    timeout: 60000,
    attestation: "direct",
  };

  return PublicKeyCredentialCreateOptions;
}

//from https://gist.github.com/pedrouid/b4056fd1f754918ddae86b32cf7d803e
async function parsePublicKey(pubKey) {
  if (pubKey["1"] === 2) {
    // we are dealing with ES256
    return window.crypto.subtle.importKey(
      "jwk",
      {
        //this is an example jwk key, other key types are Uint8Array objects
        kty: "EC",
        crv: "P-256",
        x: encode(pubKey["-2"]),
        y: encode(pubKey["-3"]),
        ext: true,
      },
      {
        //these are the algorithm options
        name: "ECDSA",
        namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
      },
      false, //whether the key is extractable (i.e. can be used in exportKey)
      ["verify"] //"verify" for public key import, "sign" for private key imports
    );
  } else if (pubKey["1"] === 3) {
    //we are dealing with RD245
    return window.crypto.subtle.importKey(
      "jwk",
      {
        kty: "RSA",
        alg: "RS256",
        n: encode(pubKey["-1"]),
        e: encode(pubKey["-2"]),
        ext: true,
      },
      {
        //these are the algorithm options
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      false, //whether the key is extractable
      ["verify"]
    );
  } else {
    throw "Unsupported type of a public key";
  }
}

//parse authData to get credentialId and pulickKey object
async function parseAuthData(authData) {
  let result = { publicKey: null, credentialId: null };
  let attCredData = authData.slice(37);

  let credIdLength = (attCredData[16] << 8) + attCredData[17]; //these two bytes needs to be "concatenated"

  if (credIdLength > 1023) {
    throw "The attestedCredentialData.credentialId is larger than allowed. Should be at most 1023.";
  }

  result.credentialId = encode(attCredData.slice(18, 18 + credIdLength));
  let publicKeyBytes = attCredData.slice(18 + credIdLength);
  let publicKey = CBOR.decode(publicKeyBytes.buffer);
  result.publicKey = await parsePublicKey(publicKey); //will return crypto.subtle.CryptoKey instance
  return result;
}

async function verify_rpIpHash(obj) {
  let encoder = new TextEncoder("utf-8");
  let hash = await window.crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(encoder.encode(RP_ID))
  );
  let rpIdHash = obj.slice(0, 32);

  if (JSON.stringify(new Uint8Array(hash)) !== JSON.stringify(rpIdHash)) {
    throw "Verification of rpIdHash failed.";
  }
}

// -------------------------------------
//      Registration
// -------------------------------------

function createUserRegistrationObject() {
  return {
    id: null,
    rawId: null,
    userName: null,
    response: { attestationObject: null, clientDataJSON: null },
    publicKeyObject: { credentialId: null, publicKey: null },
  };
}

async function register() {
  let userName = document.getElementById("input-user-name").value;
  let PublicKeyCredentialCreateOptions = await getCreateOptions(userName);

  let userRegistration = createUserRegistrationObject();
  1;
  userRegistration.userName = userName;

  console.log("REGISTRATION OPTIONS");
  console.log(PublicKeyCredentialCreateOptions);

  let credentials = await navigator.credentials.create({
    publicKey: PublicKeyCredentialCreateOptions,
  });

  userRegistration.id = credentials.id;
  userRegistration.rawId = credentials.rawId;
  let response = credentials.response;

  let clientData = parseClientDataJSON(response.clientDataJSON);
  validateClientData(
    clientData,
    PublicKeyCredentialCreateOptions.challenge,
    "webauthn.create"
  );

  userRegistration.response.clientDataJSON = clientData;
  let hash = await window.crypto.subtle.digest(
    "SHA-256",
    response.clientDataJSON
  ); //https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest

  let attestationObject = CBOR.decode(response.attestationObject);
  verify_rpIpHash(attestationObject.authData);
  userRegistration.response.attestationObject = attestationObject;

  let publicKeyObject = await parseAuthData(attestationObject.authData);
  checkCredentialId(publicKeyObject.credentialId);

  userRegistration.publicKeyObject = publicKeyObject;
  users.push(userRegistration);

  console.log("REGISTRATION RESPONSE");
  console.log(userRegistration);
}

function getAuthenticationOptions(userName) {
  let options = {
    challenge: window.crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: getCredentials(userName),
    timeout: 60000,
  };
  return options;
}

async function verifySignature(key, signature, data) {
  let algorithm;
  if (key.algorithm.name === "ECDSA") {
    algorithm = {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    };
  } else {
    algorithm = {
      name: "RSASSA-PKCS1-v1_5",
    };
  }
  return await window.crypto.subtle.verify(algorithm, key, signature, data);
}

function concat(buffer1, buffer2) {
  // curtesy of https://gist.github.com/72lions/4528834
  var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp.buffer;
}

function verifyIdFromAllowedCredentials(id, allowCredentials) {
  let tmp = allowCredentials.filter(
    (user) => id === encode(new Uint8Array(user.id))
  );
  if (tmp.length > 0) {
    return true;
  } else {
    return false;
  }
}

function getUserById(id) {
  return users.find((user) => user.id === id);
}

// -------------------------------------
//      Authorization
// -------------------------------------

async function authenticate() {
  let userName = document.getElementById("input-user-name").value;
  let options = getAuthenticationOptions(userName);

  if (options.allowCredentials.length === 0) {
    throw "There is no user registered with that user name";
  }
  console.log("AUTHENTICATION OPTIONS");
  console.log(options);

  const assertion = await navigator.credentials.get({
    publicKey: options,
  });

  // 5th step
  if (!verifyIdFromAllowedCredentials(assertion.id, options.allowCredentials)) {
    throw "The returned credentials are not from options.allowCredentials";
  }
  let user = getUserById(assertion.id);

  let response = assertion.response;
  let clientData = parseClientDataJSON(response.clientDataJSON);
  validateClientData(clientData, options.challenge, "webauthn.get");

  let authData = response.authenticatorData;
  verify_rpIpHash(new Uint8Array(response.authenticatorData));

  let signature = response.signature;
  let hash = await window.crypto.subtle.digest(
    "SHA-256",
    response.clientDataJSON
  );
  //23. Using user.publicKey, verify that signature is a valid signature over the binary concatenation of authData and hash.
  if (
    !verifySignature(
      user.publicKeyObject.publicKey,
      signature,
      concat(authData, hash)
    )
  ) {
    throw "The verification of signature failed.";
  }

  //step 25
  if (response.attestationObject !== undefined) {
    let attestationObject = CBOR.decode(response.attestationObject);
    let pubKey = parseAuthData(attestationObject.authData);

    if (pubKey.credentialId !== user.publicKeyObject.credentialId) {
      throw "The response.credentialId is not equal to credentialId from credentialRecord";
    }
    if (pubKey.publicKey !== user.publicKeyObject.publicKey) {
      throw "The response.publicKey is not equal to publicKey from credentialRecord";
    }
    user.response.attestationObject = attestationObject;
    user.response.clientData = clientData;
  }
}
