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
        await register();
    document.getElementById('success-register').style.display = "block";
    } catch (e) {
        displayError(e.message);
    }

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
    await authenticate();

    
    try {
        //TODO: this was success -> display success page
        document.getElementById('success-auth').style.display = "block";
        document.getElementById('my-form').style.display = "none";
    } catch (e) {
        displayError(e.message);
    }


});

let restoreBtn = document.getElementById('restore-btn');
restoreBtn.addEventListener("click", function(event){
    restore();
})

// ----- test method

let testBtn = document.getElementById('test-btn');
testBtn.addEventListener("click", function(event){
    var initial = { Hello: "World" };
    var encoded = CBOR.encode(initial);
    console.log(encoded);
    var decoded = CBOR.decode(encoded);
    console.log(decoded);
})
