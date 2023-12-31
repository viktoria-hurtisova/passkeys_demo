$( function(){
    console.log("we are at the start");
    
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

    });

    $("#auth-btn").click(function(ev) {
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
    });
});
