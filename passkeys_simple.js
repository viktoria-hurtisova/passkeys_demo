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

function writeDebugInfo(text) {
  let debugInfo = document.getElementById("debug_info");
  debugInfo.innerHTML += text;
}

function parseClientDataJSON(input) {
  const utf8Decoder = new TextDecoder("utf-8");
  const decodedClientData = utf8Decoder.decode(input);
  return JSON.parse(decodedClientData);
}

function validateClientData(clientData, challenge) {
  if (clientData.type !== "webauthn.create") {
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

let users = [];
let userRegistration = {
  id: null,
  rawId: null,
  userName: null,
  response: { attestationObject: null, clientDataJSON: null },
  publicKeyObject: { credentialId: null, publicKey: null },
};

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
    },
    user: {
      id: randomId, //TODO: check in which format it should be from the documentation
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

//parse authData to get credentialId and pulickKey object
function parseAuthData(authData) {
  let result = { publicKey: null, credentialId: null };
  let attCredData = authData.slice(37);

  let credIdLength = (attCredData[16] << 8) + attCredData[17]; //these two bytes needs to be "concatenated"

  if (credIdLength > 1023) {
    throw "The attestedCredentialData.credentialId is larger than allowed. Should be at most 1023.";
  }

  result.credentialId = attCredData.slice(18, 18 + credIdLength);
  let publicKeyBytes = attCredData.slice(18 + credIdLength);
  result.publicKey = CBOR.decode(publicKeyBytes.buffer);
  return result;
}

async function register() {
  let userName = document.getElementById("input-user-name").value;
  let PublicKeyCredentialCreateOptions = await getCreateOptions(userName);
  userRegistration.userName = userName;

  let credentials = await navigator.credentials.create({
    publicKey: PublicKeyCredentialCreateOptions,
  });
  //console.log(credentials);

  userRegistration.id = credentials.id;
  userRegistration.rawId = credentials.rawId;
  let response = credentials.response;
  let clientData = parseClientDataJSON(response.clientDataJSON);
  validateClientData(clientData, PublicKeyCredentialCreateOptions.challenge);

  userRegistration.response.clientDataJSON = clientData;
  //console.log(clientData);
  let hash = await window.crypto.subtle.digest(
    "SHA-256",
    response.clientDataJSON
  ); //https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest

  let attestationObject = CBOR.decode(response.attestationObject);
  userRegistration.response.attestationObject = attestationObject;
  //console.log(attestationObject);

  let publicKeyObject = parseAuthData(attestationObject.authData);
  checkCredentialId(publicKeyObject.credentialId);

  userRegistration.publicKeyObject = publicKeyObject;

  users.push(userRegistration);
  console.log(users);
}

function getAuthenticationOptions(userName) {
  let options = {
    challenge: window.crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: getCredentials(userName),
    timeout: 60000,
  };
  return options;
}

async function authenticate() {
  let userName = document.getElementById("input-user-name").value;
  let options = getAuthenticationOptions(userName);

  const assertion = await navigator.credentials.get({
    publicKey: options
  });

  console.log(assertion);
  let response = assertion.response;
  /* 4th point
  if (options.allowCredentials.filter((user) => user.id === ))
  */
}
