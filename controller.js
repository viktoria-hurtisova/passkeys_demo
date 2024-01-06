
function isFormValid() {
    
}

function displayError(message){
    document.getElementById('error').innerText = message;
    document.getElementById('error').style.display = "block";
}

if (!window.PublicKeyCredential) {
    document.getElementById('my-form').style.display = "none";
    document.getElementById('passkeys-not-supported').style.display = "none";
}

function restore(){
    document.getElementById('my-form').style.display = "block";
    document.getElementById('success-register').style.display = "none";
    document.getElementById('error').style.display = "none";
    document.getElementById('success-auth').style.display = "none";
    document.getElementById('passkeys-not-supported').style.display = "none";
}

// -------------------------------------
//      Registration
// -------------------------------------

let registerBtn = document.getElementById('register-btn');
registerBtn.addEventListener("click", async function(event) {
    restore();

    var form = document.getElementById('my-form');
    if (form.checkValidity() === false) {
        return;
    }
    event.preventDefault();

    try {
        register();
    } catch (e) {
        displayError(e.message);
    }

    //TODO: this was success -> display success page
    document.getElementById('success-register').style.display = "block";
});


// -------------------------------------
//      Authorization
// -------------------------------------

let authBtn = document.getElementById("auth-btn");
authBtn.addEventListener("click", async function(event) {
    restore();
    
    var form = document.getElementById('my-form');
    if (form.checkValidity() === false) {
        return;
    }
    event.preventDefault();

    try {
        authenticate();
    } catch (e) {
        displayError(e.message);
    }

    //TODO: this was success -> display success page
    document.getElementById('success-auth').style.display = "block";
    document.getElementById('my-form').style.display = "none";

});

let restoreBtn = document.getElementById('restore-btn');
restoreBtn.addEventListener("click", function(event){
    restore();
})

let testBtn = document.getElementById('test-btn');
testBtn.addEventListener("click", function(event){
    let randomId = window.crypto.getRandomValues(new Uint8Array(32));
    //writeDebugInfo("random id: " + randomId);
    let documentationId = Uint8Array.from(window.atob("ufJWp8YGlibm1Kd9XQBWN1WAw2jy5In2Xhon9HAqcXE="), c=>c.charCodeAt(0));
    //writeDebugInfo("documentation id: " + documentationId);
    
    writeDebugInfo("my id len: " + randomId.length + "   ");
    writeDebugInfo("doc id len: " + documentationId.length + "   ");
    

})
