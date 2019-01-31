var express = require('express');
var router = express.Router();
var ActiveDirectory = require('activedirectory');
var PropertiesReader = require('properties-reader');
var properties = PropertiesReader('adeai.properties');
var winston = require('winston');
var async = require('async');
var Joi = require('joi');

// winston log configuration for the application, logging to log/adeai.log, rotate daily
winston.add(require('winston-daily-rotate-file'), {
  filename: 'log/adeai.log',
  level: 'info',
  json: true,
  prepend: true,
  datePattern: 'yyyy-MM-dd.',
  timestamp: true
});

// simple page to test that webseal is passing headers as an authenticated user
// need to permit acl access to this page to authenticated users
router.get('/whoami', function(req, res, next) {
  var headers = {
    user: req.get('iv-user'),
    groups: req.get('iv-groups'),
    websealhost: req.get('iv_server_name'),
    authenticatedby: req.get('authenticatedby'),
  };
  res.render('index', headers);
});


/* GET home page. Redirect to /login */
router.get('/', function(req, res, next) {
  res.redirect('/login');
});

/* GET login page. */
// will display errors based on query params set by errResponse
// you'll need the MACROS turned on for LRR on WebSEAL for this as well. 
router.get('/login', function(req, res, next) {
  var options = {
    title: 'Active Directory EAI Login'
  };
  if (req.query.error == 49) {
    options.error = 'invalid username or password...';
    res.render('login', options);
  } else if (req.query.error) {
      options.error = 'something has gone horribly wrong...';
      res.render('login', options);
  } else if (req.query.ERROR_CODE == '0x38cf05e7') {
      res.redirect('/whoami');
  } else if (req.query.ERROR_CODE == '0x00000000' && req.query.TAM_OP == 'login') {
      res.render('login', options);
  } else if (req.query.ERROR_CODE == '0x38cf0427') {
      options.error = 'Forbidden';
      options.tam_error = req.query.ERROR_CODE;
      res.render('webseal_error', options);
  } else if (req.query.ERROR_CODE) {
      options.error = req.query.ERROR_CODE;
      options.tam_erro = req.query.ERROR_CODE;
      res.render('webseal_error', options);
  } else
      res.render('login', options);
});

// Actual EAI, taking posts to /login
// needs to be set as a eai trigger on webseal
router.post('/login', function(req, res, next) {

  // get properties from adeai.properties file for AD to connect to.
  var adurl = properties.get('main.ad_url');
  var adbasedn = properties.get('main.ad_basedn');
  var addomain = properties.get('main.ad_domain');
  var aduser = properties.get('main.ad_user');
  var adpass = properties.get('main.ad_pass');

  // grab the username & password that were posted.
  var username = req.body.username + addomain;
  var password = req.body.password;
  var samname = req.body.username;

  //set options and config for connecting to Active Directory
  var options = {
    includeMembership: ['user'],
    timeout: 5000,
    tlsOptions: {
      'rejectUnauthorized': false
    },
    idleTimeout: 15000
  };
  var config = {
    url: adurl,
    baseDN: adbasedn,
    username: aduser,
    password: adpass,
    tlsOptions: {
      'rejectUnauthorized': false
    },
    attributes: {
      user: ['sAMAccountName', 'userPrincipalName', 'dn']
    }
  };
  var ad = new ActiveDirectory(config);

  // set var for the session data for our user.
  var sessionData = {};

  async.series([
    // validate the username, return an error if it isn't alphanumeric 3 - 45 characters.
    function(callback) {
      var schema = Joi.object().keys({
        username: Joi.string().alphanum().min(3).max(45).required()
      });
      var validUsername = Joi.validate({
        username: samname
      }, schema);
      if (validUsername.error) {
        winston.info('Username validation failed for ' + samname);
        errorResponse(49);
        return;
      } else {
        return callback();
      }
    },
    // authenticate the user against Active Directory
    function(callback) {
      ad.authenticate(username, password, function(err, auth) {
        if (err) {
          winston.info('Authentication error for user - ' + username + ': ' + JSON.stringify(err));
          errorResponse(err);
          return;
        }
        if (auth) {
          winston.info('Successfully Authenticated - ' + username);
          return callback();
        } else {
          winston.info('Authentication error for user - ' + username + ': ' + JSON.stringify(err));
          errorResponse(err);
          return;
        }
      });
    },
    // find the user and return the LDAP attributes set in the options & config above.
    function(callback) {
      ad.findUser(options, samname, function(err, user) {
        if (err) {
          winston.info('Lookup error for user - ' + samname + ' ' + JSON.stringify(err));
          errorResponse(err);
          return;
        }
        if (!user) {
          winston.info('User: ' + samname + ' not found.');
          errorResponse(err);
          return;
        } else {
          winston.info("User and Group lookup for " + samname + " successful");
          sessionData.user = user;
          // prevent access for accounts in Administrators OU (example)
          if (sessionData.user.dn.includes("Administrators")) {
            winston.info("User DN not valid for Access: " + sessionData.user.dn);
            //redirect for invalid username/password
            res.redirect('/login?error=49');
            return;
          }
          return callback();
        }
      });
    },
    // expand the webseal cred that we will send back.
    function(callback) {
      // set email address value
      if (sessionData.user.userPrincipalName) {
        sessionData.user.emailaddress = sessionData.user.userPrincipalName.toLowerCase();
      } else {
        sessionData.user.emailaddress = "noaccess";
      }

      // set the ISAM group values, groups must exist in the registry used by ISAM servers. 
      if (sessionData.user.dn.includes("Finance")) {
        sessionData.user.tamgroups = "finance";
      } else if (sessionData.user.dn.includes("Contractor")) {
        sessionData.user.tamgroups = "contractor";
      } else {
        sessionData.user.tamgroups = "employee";
      }

      winston.info("ISAM cred created successfully for " + sessionData.user.sAMAccountName);
      return callback();
    },
    // send the response back to WebSEAL.
    function(callback) {
      sendResponse(sessionData);
      return callback();
    }
  ]);

  // error handler
  // really need better error handling for this!
  function errorResponse(err) {
      // just return invalid username or password
      res.redirect('/login?error=49');
  }

  // send the eai response by setting the required eai headers to let WebSEAL build a credential.
  function sendResponse(sessionData) {
    if (sessionData.user) {
      // log the response headers
      winston.info("Sending response for " + sessionData.user.sAMAccountName + ", Groups = " + sessionData.user.tamgroups + ", Email = " + sessionData.user.emailaddress);

      // send headers to ISAM
      res.setHeader("am-eai-ext-user-id", sessionData.user.sAMAccountName);
      res.setHeader("am-eai-ext-user-groups", sessionData.user.tamgroups);
      res.setHeader("am-eai-xattrs", "tagvalue_email,tagvalue_always,authenticatedby");
      res.setHeader("tagvalue_email", sessionData.user.emailaddress);
      res.setHeader("tagvalue_always", "authenticatedby");
      res.setHeader("authenticatedby", "adeai");

      // can set redirect url for eai if we want.  leaving in for reference.
      // res.setHeader("am-eai-redir-url", "/whoami");

      // Enable below for all environments (dev, stage, prod)
      res.end();

      // Enable below for local testing, comment code when you build the docker container.
      // res.status(200).json({
      //   'message': 'login successful'
      // });

    } else {
      // generic handler if something else goes wrong.
      res.redirect('/login?error=49');
      return;
    }
  }

});

module.exports = router;
