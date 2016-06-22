'use strict';

var crypto = require('crypto');

// Constants
var U2F_VERSION = "U2F_V2";
var PUBKEY_LEN = 65;

var errors = {
  registration: {
    NO_CLIENT_DATA: 101,
    NO_TYPE: 102,
    WRONG_TYPE: 103,
    CHALLENGE_MISMATCH: 104,
    NO_REGISTRATION_DATA: 105,
    WRONG_RESERVED_BYTE: 106,
    PUBLIC_KEY_ERROR: 107,
    SIGNATURE_INVALID: 108,
  },
  authentication: {
    NO_KEY_HANDLE: 201,
    NO_CLIENT_DATA: 202,
    NO_SIGNATURE_DATA: 203,
    WRONG_KEY_HANDLE: 204,
    NO_TYPE: 205,
    WRONG_TYPE: 206,
    CHALLENGE_MISMATCH: 207,
    SIGNATURE_INVALID: 208,
  }
};

exports.errors = errors;

/**
 * Initiates the registration of a device.
 *
 * @param appId the U2F AppID. This must be the https:// url of the site or localhost
 * @return a registration request which must be stored (temporarily) on the server and 
 * sent to the client.
 */
exports.startRegistration = function(appId, registeredKeys, options) {
  var options = options || {};

  if(typeof registeredKeys === 'undefined' || !Array.isArray(registeredKeys)) {
    return Promise.reject("registeredKeys must be an array");
  }

  var challenge = generateChallenge();

  var request =  {
    appId: appId,
    type: 'u2f_register_request',
    registerRequests: [{
      version: U2F_VERSION,
      challenge: base64_to_RFC4648(challenge)
    }],
    registeredKeys: [],
  };

  for(var index in registeredKeys) {
    request.registeredKeys.push({version: U2F_VERSION, keyHandle: registeredKeys[index].keyHandle});
  }

  if(typeof options.timeoutSeconds !== 'undefined') {
    request.timeoutSeconds = options.timeoutSeconds;
  }

  if(typeof options.requestId !== 'undefined') {
    request.requestId = options.requestId;
  }

  return Promise.resolve(request);
};

/**
 * Finishes a previously started registration.
 *
 * @param challenge The challenge sent to the client.
 * @param deviceResponse The response from the device/client.
 * @return a DeviceRegistration object, holding information about the registered device. Servers should
 * persist this.
 */
exports.finishRegistration = function(registrationRequest, registrationResponse){

  var registration = {};

  // First, check the "clientData" part
  if (!registrationResponse.clientData) { 
    return Promise.reject('No client data')
  }

  // it is a base64-encoded JSON string.
  var rawClientData = (new Buffer(registrationResponse.clientData, 'base64')).toString();
  var clientData = JSON.parse(rawClientData);

/* Not sure where these types come from..?
  if (!clientData.typ) { throw errors.registration.NO_TYPE; }
  if (clientData.typ !== "navigator.id.finishEnrollment") { throw errors.registration.WRONG_TYPE; }
*/

  // Check challenges match
  if (clientData.challenge !== registrationRequest.registerRequests[0].challenge) { 
    return Promise.reject('Challenge mismatch')
  }

  // Then, the "registrationData" part.
  if (!registrationResponse.registrationData) { 
    return Promise.reject('No registration data')
  }

  var offset = 0
  var registrationData = new Buffer(registrationResponse.registrationData, 'base64');
  // Read reserved byte
  var reservedByte = registrationData.readInt8(offset++);

  if (reservedByte !== 0x05) { 
    return Promise.reject('Incorrect reserved byte')
  }

  // Read public key
  var publicKey = registrationData.slice(offset, offset + PUBKEY_LEN);
  var tmpKey = pubKeyToPem(publicKey);
  if (!tmpKey) { 
    return Promise.reject('Public key error')
  }

  registration.publicKey = publicKey.toString('base64');
  offset += PUBKEY_LEN;

  // Read key handle
  var keyHandleLength = registrationData.readUInt8(offset++);
  var keyHandle = registrationData.slice(offset, offset+keyHandleLength);
  registration.keyHandle = keyHandle.toString('base64');
  offset += keyHandleLength;

  // Read certificate
  // length of certificate is stored in byte 3 and 4 (excluding the first 4 bytes)
  var certificateLength = 4;
  certificateLength += (registrationData.readUInt8(offset + 2) << 8); // upper byte
  certificateLength += (registrationData.readUInt8(offset + 3) << 0); // lower byte
  var rawCertificate = registrationData.slice(offset, offset+certificateLength);
  var certificate = certToPem(rawCertificate);
  registration.certificate = certificate;
  offset += certificateLength;

  // Read signature
  var signature = registrationData.slice(offset);
  var dataToVerify = "00";
  dataToVerify += hash('sha256', registrationRequest.appId);
  dataToVerify += hash('sha256', rawClientData);
  dataToVerify += keyHandle.toString('hex');
  dataToVerify += publicKey.toString('hex');
  dataToVerify = new Buffer(dataToVerify, 'hex')

  var verifier = crypto.createVerify('sha256');
  verifier.update(dataToVerify);

  var is_valid = verifier.verify(registration.certificate, signature);
  if(!is_valid) { 
    return Promise.reject('Signature invalid')
  }

  return Promise.resolve(registration);
};

/**
 * Initiates the authentication process.
 *
 * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
 * support logging in from multiple Web Origins.
 * @param deviceRegistration the DeviceRegistration for which to initiate authentication.
 * @return a StartedAuthentication which should be sent to the client and temporary saved by
 * the server.
 */
exports.startAuthentication = function(appId, registeredKeys, options){
  var options = options || {};

  if(typeof appId === 'undefined') {
    return Promise.reject('Authentication request requires appId')
  }

  if(typeof registeredKeys === 'undefined') {
    return Promise.reject('Authentication request requires registeredKeys')
  }

  var challenge = generateChallenge();

  var request = {
    appId: appId,
    type: 'u2f_sign_request',
    challenge: challenge,
    registeredKeys: []
  };

  for(var index in registeredKeys) {
    request.registeredKeys.push({version: U2F_VERSION, keyHandle: registeredKeys[index].keyHandle});
  }

  if(typeof options.timeoutSeconds !== 'undefined') {
    request.timeoutSeconds = options.timeoutSeconds;
  }

  if(typeof options.requestId !== 'undefined') {
    request.requestId = options.requestId;
  }

  return Promise.resolve(request);
};

/**
 * Finishes a previously started authentication.
 *
 * @param challenge The challenge sent to the client.
 * @param deviceResponse The response from the device/client.
 * @param deviceRegistration the DeviceRegistration for which the authentication was initiated.
 * @param response the response from the device/client.
 */
exports.finishAuthentication = function(challenge, deviceResponse, registeredKeys){
  // Validation
  if (!deviceResponse.keyHandle) { 
    return Promise.reject('Response must contain key handle') 
  }
  if (!deviceResponse.clientData) { 
    return Promise.reject('Response must contain client data') 
  }
  if (!deviceResponse.signatureData) { 
    return Promise.reject('Response must contain signature data') 
  }
  if (typeof registeredKeys === 'undefined' || !Array.isArray(registeredKeys) || registeredKeys.length == 0) { 
    return Promise.reject('Registered keys array is required') 
  }

  // Check response key handle was issued in the challenge
  var usedKey = registeredKeys.find(function(item) {
    return item.keyHandle == deviceResponse.keyHandle;
  }) || null;
  if (usedKey == null) { 
    return Promise.reject('Invalid key handle') 
  }

  if(typeof usedKey.publicKey === 'undefined') {
    return Promise.reject('Registered key matching handle does not contain public key') 
  }

  // Parse client data
  var rawClientData = (new Buffer(deviceResponse.clientData, 'base64')).toString();
  var clientData = JSON.parse(rawClientData);

  /* Not sure where these types come from..?
  if (!clientData.typ) { 
    return Promise.reject('Client data should contain type specifier') 
  }
  if (clientData.typ !== "navigator.id.getAssertion") { 
    return Promise.reject('Incorrect type specified in client data') 
  }
  */
  if (clientData.challenge !== challenge.challenge) { 
    return Promise.reject('Authentication challenge mismatch') 
  }

  var signatureData = new Buffer(deviceResponse.signatureData, 'base64');

  var dataToVerify = "";
  dataToVerify += hash('sha256', challenge.appId);
  dataToVerify += signatureData.slice(0, 5).toString('hex');
  dataToVerify += hash('sha256', rawClientData);
  dataToVerify = new Buffer(dataToVerify, 'hex');

  var signature =  signatureData.slice(5);

  var pubKey = new Buffer(usedKey.publicKey, 'base64');

  // Transform the public key to PEM format, because that's what crypto wants.
  var pemPubKey = pubKeyToPem(pubKey);

  var verifier = crypto.createVerify('sha256');
  verifier.update(dataToVerify);
  var is_valid = verifier.verify(pubKeyToPem(pubKey), signature);
  if(!is_valid) { 
    return Promise.reject('Invalid authentication signature') 
  }

  // Get counter and user presence info
  var userPresence = signatureData.readUInt8(0); // should equal 1
  var counter = signatureData.readUInt32BE(1); // should always be incrementing, and wrap around

  return Promise.resolve({
    userPresence: userPresence,
    counter: counter
  });
};

/**************************************************/
/*             UTILITY FUNCTIONS                  */
/**************************************************/



var base64_to_RFC4648 = function(input) {
  // RFC 4648 uses '-' instead of '+', and '_' instead of '/'.
  return input.replace(/\+/g, '-').replace(/\//g, '_');
}

var pubKeyToDER = function(key) {
  if(key.length !== 65 || key[0] !== 0x04) {
    console.error("Key NOT OK!");
    console.error(key.length);
    console.error(key[0]);
    return;
  }
  /*
   * Convert the public key to binary DER format
   * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
   *
   *  SEQUENCE(2 elem)                        30 59
   *   SEQUENCE(2 elem)                       30 13
   *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
   *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
   *   BIT STRING(520 bit)                    03 42 00 ..key..
   */
  var der  = ""
  der += "3059";
  der += "3013";
  der += "06072a8648ce3d0201";
  der += "06082a8648ce3d030107";
  der += "034200" + key.toString("hex");
  return der;
}

var pubKeyToPem = function(key) {
  var der = pubKeyToDER(key);
  var der_buf = new Buffer(der, 'hex');
  var der_64 = der_buf.toString('base64');

  var pem = "";
  pem  = "-----BEGIN PUBLIC KEY-----\n";
  while(der_64.length) {
    pem += der_64.slice(0, 64) + "\n";
    der_64 = der_64.slice(64);
  }
  pem += "-----END PUBLIC KEY-----";
  return pem;
};

var certToPem = function(cert_buf) {
  var cert_64 = cert_buf.toString('base64');

  var pem = "";
  pem += "-----BEGIN CERTIFICATE-----\n";
  while(cert_64.length) {
    pem += cert_64.slice(0, 64) + "\n";
    cert_64 = cert_64.slice(64);
  }
  pem += "-----END CERTIFICATE-----";
  return pem;
};

var hash = function(algo, data){
  var hasher = crypto.createHash(algo);
  hasher.update(data);
  return hasher.digest('hex');
};

var generateChallenge = function() {
  return crypto.randomBytes(32).toString('base64');
};
