const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");

loginForm.addEventListener("submit", function(event) {

    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();


    if (email === "" || password === "") {

        loginMessage.textContent = "Please enter your email and password.";

        loginMessage.style.color = "#ff3038";

        return;
    }


    /*
       Demo login

       For now, any non-empty email and password
       will allow the user to enter the application.
    */

    loginMessage.textContent = "Login successful. Redirecting...";

    loginMessage.style.color = "#35e58a";


    // Save login state

    localStorage.setItem("hackVortexLoggedIn", "true");

    localStorage.setItem("hackVortexUser", email);


    // Go to scanner / landing page

    setTimeout(function() {

        window.location.href = "landing.html";

    }, 800);

});