import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

// Secret key to use for signing messages.
const kServerSecretKey = generateRandomness();

// Generates a token to protect against Cross Site Request Forgery by embedding
// the token into forms and verifying it when processing the input.
const generateTransactionToken = session => {
  return HMAC(kServerSecretKey, session.username + session.hashedPassword + session.salt);
}

// Signs the input session and stores the signature in session.signature.
const signSession = session => {
  const sess = JSON.parse(JSON.stringify(session));
  sess.signature = "";
  session.signature = HMAC(kServerSecretKey, JSON.stringify(sess));
  return session;
}

// Verifies the session is signed and valid.
const isValidSession = session => {
  const sess = JSON.parse(JSON.stringify(session));
  sess.signature = "";
  return HMAC(kServerSecretKey, JSON.stringify(sess)) == session.signature;
}

// Only alphanumeric usernames are supported.
const isValidUsername = username => {
  return username.match(/^[a-z0-9]+$/i) !== null;
}

// The function works by escaping all potentially malicious characters.
// Source: https://stackoverflow.com/questions/1787322/htmlspecialchars-equivalent-in-javascript/4835406#4835406
const escapeHtml = text => {
  if (text == false) return false;
  var map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };

  return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

const cleanAccount = account => {
  const newAccount = JSON.parse(JSON.stringify(account));
  if (account == null) return account
  if (account.profile != null) {
    newAccount.profile = escapeHtml(account.profile);
  }
  if (account.username != null) {
    newAccount.username = escapeHtml(account.username)
  }
  return newAccount;
}

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite', { cached: true });

const render = (req, res, next, page, title, errorMsg = false, result = null) => {
  res.render(
    'layout/template', {
      page,
      title: escapeHtml(title),
      loggedIn: req.session.loggedIn,
      account: req.session.account,
      errorMsg: escapeHtml(errorMsg),
      result: cleanAccount(result),
    }
  );
}

// Redirects the user to the home page due to an invalid session!
const invalidSession = (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', "Invalid session detected! Logging out for safety.", {token: null});
}

router.get('/', (req, res, next) => {
  if (req.session.loggedIn == true && !isValidSession(req.session)) return invalidSession(req, res, next);
  render(req, res, next, 'index', 'Bitbar Home', false, {token: generateTransactionToken(req.session)});
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {
  if (!isValidSession(req.session)) return invalidSession(req, res, next);
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  if (req.body.token != generateTransactionToken(req.session)) {
    render(req, res, next, 'index', 'Bitbar Home', 'Something is amiss with updating your profile! Try again', {token: generateTransactionToken(req.session)});
    return;
  }
  req.session.account.profile = escapeHtml(req.body.new_profile);
  req.session = signSession(req.session);
  console.log(req.body.new_profile);
  const db = await dbPromise;
  const query = `UPDATE Users SET profile = $profile WHERE username = $user;`;
  const result = await db.run(query, {$profile: req.body.new_profile, $user: req.session.account.username});
  render(req, res, next, 'index', 'Bitbar Home', false, {token: generateTransactionToken(req.session)});

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.post('/post_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == $user;`;
  const result = await db.get(query, {$user: req.body.username});
  if(result) { // if this username actually exists
    if(checkPassword(req.body.password, result)) { // if password is valid
      req.session.loggedIn = true;
      req.session.account = result;
      req.session = signSession(req.session);
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    }
  }
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});

router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  if (!isValidUsername(req.body.username)) {
    render(req, res, next, 'register/form', 'Register', "Usernames must be alphanumeric.");
    return;
  }
  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == $user;`;
  let result = await db.get(query, {$user: req.body.username});
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  req.session = signSession(req.session);
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  if (!isValidSession(req.session)) return invalidSession(req, res, next);
  const db = await dbPromise;
  const query = `DELETE FROM Users WHERE username == $user;`;
  await db.get(query, {$user: req.session.account.username});
  req.session.loggedIn = false;
  req.session.account = {};
  req.session.signature = "";
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  if (!isValidSession(req.session)) return invalidSession(req, res, next);
  req.session.loggedIn = false;
  req.session.account = {};
  req.session.signature = "";
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  if (!isValidSession(req.session)) return invalidSession(req, res, next);
  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == $user;`;
    let result;
    try {
      result = await db.get(query, {$user: req.query.username});
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));


router.get('/transfer', (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  if (!isValidSession(req.session)) return invalidSession(req, res, next);
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false,
    {receiver:null, amount:null, token: generateTransactionToken(req.session)});
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  if (!isValidSession(req.session)) return invalidSession(req, res, next);
  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null, token: generateTransactionToken(req.session)});
    return;
  }

  if (req.body.token != generateTransactionToken(req.session)) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Something looks wrong with your submission! Please try again!', {receiver:null, amount:null, token: generateTransactionToken(req.session)});
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == $user;`;
  const receiver = await db.get(query, {$user: req.body.destination_username});
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null, token: generateTransactionToken(req.session)});
      return;
    }

    req.session.account.bitbars -= amount;
    req.session = signSession(req.session);
    query = `UPDATE Users SET bitbars = $bitbars WHERE username == $user;`;
    await db.run(query, {$bitbars: req.session.account.bitbars, $user: req.session.account.username});
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = $newbal WHERE username == $user;`;
    await db.run(query, {$newbal: receiverNewBal, $user: receiver.username});
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'This user does not exist!', {receiver:null, amount:null, token: generateTransactionToken(req.session)});
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});


module.exports = router;
