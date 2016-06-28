AuthDog
==================

Server side U2F/FIDO library for Node.js. Provides functionality for registering and authenticating with U2F devices.  

Based on @jacobmarshall's fork of @emilecantin's initial [implementation](https://github.com/emilecantin/node-u2flib-server). Altered to interact with the [high level interface](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-javascript-api.html#high-level-javascript-api) defined by the Fido specifications, and implemented by the [Yubico reference client api](https://demo.yubico.com/js/u2f-api.js).  

Rebuilt to support multiple u2f tokens, with a focus on simple integration (ie. human readable errors, solid input validation and sanitisation).  

Check out a simple example at [ryankurte/authdog-example](https://github.com/ryankurte/authdog-example).  

Status
------

Module is a work in progress, functionally working but needs better input validation and testing.  
API is also subject to change if anything is found to be missing or better layouts become apparent.  
CLI interface is currently fairly broken.  

[![Build Status](https://travis-ci.org/ryankurte/authdog.svg)](https://travis-ci.org/ryankurte/authdog)  [![Dependencies](https://david-dm.org/ryankurte/authdog.svg)](https://david-dm.org/ryankurte/authdog) [![NPM](https://img.shields.io/npm/v/authdog.svg)](https://www.npmjs.com/package/authdog) 


Installation
------------

```
npm install authdog
```


Usage
-----

```
var u2f = require('authdog');
```

The u2f protocol consists of two main actions:
- Registration, in which we associate specific device(s) with a user.
- Authentication, in which we verify that the user is in possession of a previously registered device.

Each of these actions consist of two phases: challenge and response.  

An application implementing U2F needs to store a set of information about tokens associated with each user account, henceforth referred to as 'token metadata' consisting of a key handle used to identify the keypair, the public key of the token, the usage count of the token, and optionally the token certificate.  

### Device Registration

To start device registration use:
```
// Generate a registration request
u2f.startRegistration(appId, existingKeys, {requestId: N, timeoutSeconds: 100})
.then(function(registrationRequest) {
  // Save registration request to session for later use
  ...

  // Send registration request to client
  ...

}, function(error) {
  // Handle registration request error
  ...

});

```

Where existingKeys is an array of token metadata for tokens already bound to the user account.  

The registration request object must be stored for use when validating the client response in the next step.  

It can then be used on the client with `u2f.register(req.appId, req.registerRequests, req.registeredKeys, registerCallback, req.timeoutSeconds);`.

To finalise device registration use:
```
// Process registration response
u2f.finishRegistration(registrationRequest, reqistrationResponse)
.then(function(registrationStatus) {
  // Save device meta structure for future authentication use
  var meta = {
    keyHandle: registrationStatus.keyHandle, 
    publicKey: registrationStatus.publicKey,
    certificate: registrationStatus.certificate
  }
  ...

}, function(error) {
  // Handle registration error
  ...

});


```

### Authentication

To start the authentication process call:
```
// Generate authentication request
var authRequest = u2f.startAuthentication(appId, existingKeys, {requestId: N, timeoutSeconds: 10});
.then(function(registrationRequest) {
  // Save authentication request to session for later use
  ...

  // Send authentication request to client
  ...
  
}, function(error) {
  // Handle authentication request error
  ...

});

```

Where existingKeys is an array of token metadata for viable authentication tokens (those registered to the users account).  

This registration request object must be stored for use when validating the client authentication response in the next step.  
It can then be used on the client with `u2f.sign(req.appId, req.challenge, req.registeredKeys, signatureCallback, req.timeoutSeconds);`.

To finalise the authentication process call:
```
// Check authentication response
u2f.finishAuthentication(signRequest, signResponse, deviceRegistration)
.then(function(authenticationStatus) {
  // Authentication ok!
  ...

}, function(error) {
  // Handle authentication error
  ...

});

```

For further examples, check out [test.js](./test.js).

Notes
-----

The high level client interface referred to above is defined as follows:
```
interface u2f {
    void register (DOMString appId, sequence<RegisterRequest> registerRequests, sequence<RegisteredKey> registeredKeys, function(RegisterResponse or Error) callback, optional unsigned long? opt_timeoutSeconds);
    void sign (DOMString appId, DOMString challenge, sequence<RegisteredKey> registeredKeys, function(SignResponse or Error) callback, optional unsigned long? opt_timeoutSeconds);
};
```

------

If you have any questions, comments, or suggestions, feel free to open an issue or a pull request.

