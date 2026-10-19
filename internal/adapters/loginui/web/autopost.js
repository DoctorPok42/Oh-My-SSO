// Submits the form of autopost.html as soon as the page is loaded (SAML
// HTTP-POST binding, Step 11). Without JavaScript, the "Continue" button
// does the same.
(() => {
  "use strict";
  const form = document.getElementById("autopost");
  if (form) form.submit();
})();
