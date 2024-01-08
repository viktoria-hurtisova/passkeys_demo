function displayError(message) {
  document.getElementById("error").innerText = message;
  document.getElementById("error").style.display = "block";
}

if (!window.PublicKeyCredential) {
  document.getElementById("my-form").style.display = "none";
  document.getElementById("passkeys-not-supported").style.display = "none";
}

function restore() {
  document.getElementById("my-form").style.display = "block";
  document.getElementById("success-register").style.display = "none";
  document.getElementById("error").style.display = "none";
  document.getElementById("success-auth").style.display = "none";
  document.getElementById("passkeys-not-supported").style.display = "none";
}

// -------------------------------------
//      Registration
// -------------------------------------

let registerBtn = document.getElementById("register-btn");
registerBtn.addEventListener("click", async function (event) {
  restore();

  var form = document.getElementById("my-form");
  if (form.checkValidity() === false) {
    return;
  }
  event.preventDefault();

  register()
    .then(function (res) {
      let userName = document.getElementById("input-user-name").value;
      document.getElementById("success-register").style.display = "block";
      document.getElementById("success-register").innerHTML =
        "<strong>Welcome, " +
        userName +
        "!</strong> You have been successfully registered and can now authenticate.";
    })
    .catch(function (e) {
      displayError(e);
    });
});

// -------------------------------------
//      Authorization
// -------------------------------------

let authBtn = document.getElementById("auth-btn");
authBtn.addEventListener("click", async function (event) {
  restore();

  var form = document.getElementById("my-form");
  if (form.checkValidity() === false) {
    return;
  }
  event.preventDefault();

  authenticate()
    .then(function (result) {
      document.getElementById("success-auth").style.display = "block";
      document.getElementById("my-form").style.display = "none";
    })
    .catch(function (e) {
      displayError(e);
    });
});

let restoreBtn = document.getElementById("restore-btn");
restoreBtn.addEventListener("click", function (event) {
  restore();
});
