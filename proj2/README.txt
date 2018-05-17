# Part 2: Defenses

## Attack Alpha
Attack Alpha relies on unsanatized user input being rendered to the page. We can avoid this attack (and other similar attacks), by simply sanatizing the user input by escaping all HTML related characters in any input provided by the user. While somewhat excessive, this is the easiest and most straight-forward way of knowing that the input is safe. Alternatively, we could keep a whitelist of allowed tags (such as <p>), but we'd rather err on the side of security. We make sure everything is sanatized by changing the render() function to sanatize values before passing them to the EJS templates.

## Attack Bravo
Attack Bravo relies on Cross-Site Request Forgery. The most straight forward way to solve this problem is to embed a secret token into the transfer page which depends on the logged in user in some way. This token should be difficult to guess. We can satisfy these requirements by simply using the HMAC function in the crypto.js library to generate a signature on the user + hashedpassword + salt data in the session (which should not change per session). The server is the only one able to generate this signature, and an attacker will be unable to guess it. This token allows us to verify the POST request is authorized by the user, since we include the token as part of the request. We do something similar for the set_profile API, and thereby prevent CSRF attacks there too.

## Attack Charlie
Attack Charlie relies mostly on the fact that all the session information is stored client-side. We can prevent client-side session attacks by signing our session with a secret, server-only key. Anytime the server starts a session, it signs it. Anytime the servers changes the session, it signs it. And anytime the server reads the session, it verifies the signature before proceeding. If the signature is invalid, we immediately log the user out and inform them of this decision.

## Attack Delta
This attack similary relies on the ability to overwrite the local cookie. We prevent it by signing the cookie and checking the signature before making any transactions.

## Attack Echo
The easiest protection against a SQL Injection attack is to simply disallow any non alphanumeric characters. In addition to this, we use only prepared statements for all of the SQL executions, thereby avoiding SQL injection entirely.

## Attack Foxtrot
We handle this attack by always sanitizing the input so we escape all HTML characters. Furthermore, with the additional verifications added to the set_profile route (we verify the user token), it makes the attack more difficult to accomplish (though not impossible).