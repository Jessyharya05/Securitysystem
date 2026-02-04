function login() {
  alert("Login success (dummy)");
  window.location.href = "dashboard.html";
}

function uploadFile() {
  const file = document.getElementById("fileInput").files[0];
  if (!file) {
    alert("Please choose a file");
    return;
  }
  alert("File encrypted & sent successfully (dummy)");
}

function download() {
  alert("File decrypted & downloaded (dummy)");
}
