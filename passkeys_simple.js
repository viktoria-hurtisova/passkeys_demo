let registerUserObj = {
    request: null, 
    response: null,
    publicKey: null,
    credentialId: null
};

function writeDebugInfo(text) {
    let debugInfo = document.getElementById("debug_info");
    debugInfo.innerHTML += text;
}

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
    write(challenge);
    console.log(clientData);
    write(Uint64Array.from(clientData.challenge, c => c.charCodeAt(0)))
    //Verify that the value of clientData.challenge equals the base64url encoding of options.challenge.
    if (b64enc(challenge) !== clientData.challenge) {
        throw "validateAttestationResponse: The challenges are not equal!";
    }

    if (window.location.origin !== clientData.origin) {
        throw "validationAttestationResponse: The origins are not equal!";
    }

    if (clientData.hashAlg || clientData.hashAlgorithm) {
        //TODO: mam si to niekde ulozit? je to tam vobec?
        //Let hash be the result of computing a hash over response.clientDataJSON using SHA-256
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

//todo https://prettier.io/ -> save, then ctrl+e

async function getCreateOptions(userName){

    let challenge = window.crypto.getRandomValues(new Uint8Array(32));
    writeDebugInfo("challenge: " + challenge);
    let randomId = window.crypto.getRandomValues(new Uint8Array(32));
    writeDebugInfo("random id: " + randomId);

    const PublicKeyCredentialCreateOptions = {
        challenge:  challenge, //should be at least 16 bytes
        rp: {
            name: "Security for SW Systems in practice"
        },
        user: {
            id: randomId,   //TODO: check in which format it should be from the documentation
            name: userName,
            displayName: userName
        },
        pubKeyCredParams: [
            {
              type: "public-key",
              alg: -7 // "ES256" as registered in the IANA COSE Algorithms registry
            },
            {
              type: "public-key",
              alg: -257 // Value registered by this specification for "RS256"
            }
        ],
        /*
        excludeCredentials: [
            // Don’t re-register any authenticator that has one of these credentials
            {"id": Uint8Array.from(window.atob("ufJWp8YGlibm1Kd9XQBWN1WAw2jy5In2Xhon9HAqcXE="), c=>c.charCodeAt(0)), "type": "public-key"},
            {"id": Uint8Array.from(window.atob("E/e1dhZc++mIsz4f9hb6NifAzJpF1V4mEtRlIPBiWdY="), c=>c.charCodeAt(0)), "type": "public-key"}
          ],
        */
        //authenticatorSelection: {
        //    authenticatorAttachment: "cross-platform",
        //},
        timeout: 60000,
        attestation: "direct"
    };  

    return PublicKeyCredentialCreateOptions;
}

async function register(){
    let userName = document.getElementById('input-user-name').value;
    let PublicKeyCredentialCreateOptions = await getCreateOptions(userName);

    registerUserObj.request = PublicKeyCredentialCreateOptions;

    let credentials = await navigator.credentials.create({
        publicKey: PublicKeyCredentialCreateOptions
    });


}

async function authenticate() {

}


    // -------------------------------------
    //      Registration
    // -------------------------------------
    function blabla(credentials){
            if (credentials !== null) {
                // section 7.1. Registering a new credential    https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
               // Send credential info to server
               write("id from challenge: " + PublicKeyCredentialCreateOptions.id);
               write("id from cred: " + credentials.id);
               registerUserObj.response = credentials;
               validateAttestationResponse(registerUserObj, credentials);
               //TODO: save the registeredUserObj somewhere?
            } 

};
        //.catch(function(err){
            //writeDebugInfo("there was some error concerning the create func \t" + err);
        //});
        

  async function bla2(ev) {

        let userName = document.getElementById('input-user-name').value;

        // creating publicKeyCredentialRequestOptions
        let challenge = await window.crypto.getRandomValues(new Uint8Array(16));
        let userId = registerUserObj.request.user.id;

        const publicKeyCredentialRequestOptions = {
            challenge: challenge,
            allowCredentials: [{  //this is an array
                id: userId,
                type: 'public-key',
                transports: ['usb', 'ble', 'nfc']
            }],
            timeout: 60000
        };

        await navigator.credentials.get({
            publickey: publicKeyCredentialRequestOptions
        }).then(function(credentails){
            let response = credential.response;
            let clientExtensionResults = credentials.getClientExtensionResults();
            if (publicKeyCredentialRequestOptions.allowCredentials){
                //from section 7.2. Verifying an Authentication Assertion
                let id = credentials.id;
                //todo -> erify that credential.id identifies one of the public key credentials listed in options.allowCredentials

                //todo decode response.clientDataJSON with UTF-8 decode (as in registration)
                    //check origin, type and challenge as in registration
                //let hash = SHA_256(clientDataJSON)  todo: find the method
                //verify that signature is valid over the binary concatenation of authenticatorData and hash

                //if response.attestationObject is present -> perform CBOR decoding on attestationObject to obtain credentialPublicKey and credentialId fileds as in the registration and check if they match with the the obtained one from registration
            }

        }).catch(function(err){

        });

        //todo: check id
        //todo: get credentials about the user
        //todo: hash the clientdata
        //todo: create signedData
        //todo verify

};

//./mongoose.exe -d . -l http://0.0.0.0:8080