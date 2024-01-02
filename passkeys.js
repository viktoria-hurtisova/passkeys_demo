$( function(){
    if (!window.PublicKeyCredential) {
        $('#myForm').hide();
        $('#passkeys-not-supported').show();
    }
    // -------------------------------------
    //      Registration
    // -------------------------------------
    
    function getDatabase() {
        const retrievedDB = JSON.parse(window.localStorage.getItem('myDatabase')) ?? [] ;
        return retrievedDB;
    }
    
    function getUsersWithSameName(userName){
        const db = getDatabase();
        let users = [];
        db.forEach((user) => {
            if (user.userName === userName)
                user.push(user);
        });
        
    }
    
    function getCredentials(userName) { //todo, nech to vracia array
        let db = getDatabase();
        const user = db.find(el => el.userName === userName);
        if (user){
            return true;
        }
        return false;
    }

    function getExcludeCredentials(userName) {
        let users = getUsersWithSameName(userName);
        let excludeCredentials = [];
        users.forEach(user => {
            excludeCredentials.push({"id": user.id});
        });

        return excludeCredentials;
    }
    
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
        let excludeCredentials = getExcludeCredentials(userName);

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
    
    if (credential === null) {
        //TODO: error message
    }

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
        let challenge = await window.crypto.getRandomValues(new Uint8Array(32));
        let user = getCredentials(userName);
        let credentialId = user.id;

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
