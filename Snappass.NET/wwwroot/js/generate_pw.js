function generatePassword() {
    var passwordLength = 24;
    var chars = "0123456789abcdefghijklmnopqrstuvwxyz!@#$§%-_<>&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var password = "";
    for (var i = 0; i <= passwordLength; i++) {
        var randomNumber = Math.floor(Math.random() * chars.length);
        password += chars.substring(randomNumber, randomNumber + 1);
    }
    document.getElementById('password').value = password;
}

document.getElementById("generate-pw").addEventListener("click", generatePassword);