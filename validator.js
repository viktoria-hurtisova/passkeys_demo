function parseClientDataJSON(input) {
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(input);
    return JSON.parse(decodedClientData);
}
// the documentation about this part is Table 1 and Table 4
// at https://www.w3.org/TR/webauthn-3/
function parseAttestationObject(input) {
    let result = {publicKey: null, credentialId: null};

    let parsed = window.CBOR.decode(input); //TODO: look at the format

    //we will get the public key from the authenticator data 
    // and the subsection attestedCredentialData
    let attCredData = parsed.authData.slice(35);
    let credIdLength = attCredData.getUint16(16); // -> this should retrieve a Uint16 from the specified byte offset
    result.credentialId = attCredData.slice(18, 18 + credIdLength);
    let publicKeyBytes = attCredData.slice(18+credIdLength);
    result.publicKey = window.CBOR.decode(publicKeyBytes);
    //TODO: look at how the publicKeyObject looks -> if it has the required format
    return result;
}

function validateAttestationResponse(registeredUserObj, res) {
    let challenge = registeredUserObj.request.challenge;
    let clientData = parseClientDataJSON(res.response.clientDataJSON);

    if (b64enc(challenge) !== clientData.challenge) {
        throw "validateAttestationResponse: The challenges are not equal!";
    }

    if (window.location.origin !== clientData.origin) {
        throw "validationAttestationResponse: The origins are not equal!";
    }

    if (clientData.hashAlg || clientData.hashAlgorithm) {
        //TODO: mam si to niekde ulozit? je to tam vobec?
    }
    if (clientData.type !== "webauthn.create"){
        throw "validateAttestationResponse: The authenticator performed an incorrect operation."
    }
    //parse the attestation object
    let parsedAttObj = parseAttestationObject(res.response.attestationObject);
    registeredUserObj.publicKey = parsedAttObj.publicKey;
    registeredUserObj.credentialId = parsedAttObj.credentialId;
    
}
// authenticator data -> in table 1 -> contains attestedCredentialData
//AttestedCredentialData -> section 6.5.2 -> there is also a table