AuthDog
==================

Server side U2F/FIDO library for Node.js. Provides functionality for registering and authenticating with U2F devices.  

Based on @jacobmarshall's fork of @emilecantin's initial [implementation](https://github.com/emilecantin/node-u2flib-server). Altered to interact with the [high level interface](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-javascript-api.html#high-level-javascript-api) defined by the Fido specifications, and implemented by the [Yubico reference client api](https://demo.yubico.com/js/u2f-api.js).

The high level interface is defined as follows:
```
interface u2f {
    void register (DOMString appId, sequence<RegisterRequest> registerRequests, sequence<RegisteredKey> registeredKeys, function(RegisterResponse or Error) callback, optional unsigned long? opt_timeoutSeconds);
    void sign (DOMString appId, DOMString challenge, sequence<RegisteredKey> registeredKeys, function(SignResponse or Error) callback, optional unsigned long? opt_timeoutSeconds);
};
```

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

### Device Registration

To start device registration use:
```
// Generate a registration request
var registerRequest = u2f.startRegistration(appId, existingKeys, {requestId: N, timeoutSeconds: 100});

// Save registration request to session for later use
...

// Send registration request to client
...

```

Where existingKeys is an array of metadata ({keyHandle: ..., publicKey: ..., certificate: ...}) for keys already bound to the user account.  

This registration request object can then be used on the client with `u2f.register(req.appId, req.registerRequests, req.registeredKeys, registerCallback, req.timeoutSeconds);`. This must be stored for use when validating the client response in the next step.

To finalise device registration use:
```
  // Process registration response
  var registrationStatus = u2f.finishRegistration(registrationRequest, reqistrationResponse);

  if(typeof registrationStatus !== 'undefined') {
    // Handle registration error
    ...

  } else {
    // Save device meta structure for future authentication use
    var meta = {
      keyHandle: registrationStatus.keyHandle, 
      publicKey: registrationStatus.publicKey,
      certificate: registrationStatus.certificate
    }
    ...

  }

```

### Authentication

To start the authentication process call:
```
// Generate authentication request
var authRequest = u2f.startAuthentication(appId, existingKeys, {requestId: N, timeoutSeconds: 10});

// Save request to session for later use
...

// Send registration request to client
...

```

Where existingKeys is an array of metadata for keys already bound to the user account ({keyHandle: ..., publicKey: ..., certificate: ...}).

This registration request object can then be used on the client with `u2f.sign(req.appId, req.challenge, req.registeredKeys, signatureCallback, req.timeoutSeconds);`. This must be stored for use when validating the client authentication response in the next step.

To finalise the authentication process call:
```
// Check authentication response
var deviceAuthentication = u2f.finishAuthentication(signRequest, signResponse, deviceRegistration);

TODO(ryankurte)

```

