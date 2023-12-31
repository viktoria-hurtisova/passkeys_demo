$( function(){
    if (!window.PublicKeyCredential) {
        $('#myForm').hide();
        $('#passkeys-not-supported').show();
    }
    // -------------------------------------
    //      Registration
    // -------------------------------------
    
    $("#register-btn").click(async function(ev) {
        var form = document.getElementById('myForm');
        if(form.checkValidity() === true) {
            ev.preventDefault();
            $("#success").show();
            $("#not-successful").hide();
        }
        else {
            $("#not-successful").show();
            $("#success").hide();
            return;
        }
        
        let userName = document.getElementById('input-user-name').value;
        // -------------------------------------
        //      Creating credentials
        // -------------------------------------

        let challenge = await window.crypto.getRandomValues(new Uint8Array(32));
        let randomId = await window.crypto.getRandomValues(new Uint8Array(16));

        const PublicKeyCredentialCreateOptions = {
            challenge:  challenge, //should be at least 16 bytes
            rp: {
                name: "Security for SW Systems in practice",
                id: "lioness-sacred-akita.ngrok-free.app/"
            },
            user: {
                id: randomId,
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
            authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
    },
    timeout: 60000,
    attestation: "direct"
    };

    const credential = await navigator.credentials.create({
        publicKey: PublicKeyCredentialCreateOptions
    });

    // ----- Parsing and validating the registration data
    console.log(credential.id); //todo remove, but look at the id, is it the same as the randomid? (its not written anywhere)
    // decode the clientDataJSON into a utf-8 string
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(
    credential.response.clientDataJSON)

    // parse the string as an object
    const clientDataObj = JSON.parse(decodedClientData);    //contains challenge, origin, type; we must validate these fields

    console.log(clientDataObj);     //todo: remove

    const decodedAttestationObj = CBOR.decode(credential.response.attestationObject);

    console.log(decodedAttestationObj); //contatins authData (publickey), ftm (attestation format), attStmt (depends on the format)

    });

    function getCredentialID(userName) {

    }

    $("#auth-btn").click(async function(ev) {
        var form = document.getElementById('myForm');
        if(form.checkValidity() === true) {
            ev.preventDefault();
            $("#success").show();
            $("#not-successful").hide();

        }
        else {
            $("#not-successful").show();
            $("#success").hide();
            return;
        }


        // creating publicKeyCredentialRequestOptions
        let challenge = await window.crypto.getRandomValues(new Uint8Array(32));
        let credentialId = getCredentialID(userName);
        const publicKeyCredentialRequestOptions = {
            challenge: challenge,
            allowedCredentials: [{
                id: credentialId,
                type: 'public-key',
                transports: ['usb', 'ble', 'nfc']
            }],
            timeout: 60000
        };

        const credentials = await navigator.credentials.get({
            publickey: publicKeyCredentialRequestOptions
        });

    });
});
