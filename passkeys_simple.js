let registerUserObj = {
    request: null, 
    response: null,
    publicKey: null,
    credentialId: null
};

import * as validator from "./validator.js"
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

        let challenge = await window.crypto.getRandomValues(new Uint8Array(16));
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
        registerUserObj.request = PublicKeyCredentialCreateOptions;

        await navigator.credentials.create({
            publicKey: PublicKeyCredentialCreateOptions
        }).then(function (credentials){
            if (credentials !== null) {
                // section 7.1. Registering a new credential    https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
               // Send credential info to server
               registerUserObj.response = credentials;
               validator.validateAttestationResponse(registerUserObj, credentials);
               //TODO: save the registeredUserObj somewhere?
            } 

        }).catch(function(err){
            // No acceptable authenticator or user refused consent
        });
        
    });


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

    });
});

//./mongoose.exe -d . -l http://0.0.0.0:8080