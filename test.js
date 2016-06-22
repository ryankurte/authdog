'use strict';

var assert = require('assert');
var VirtualToken = require('virtual-u2f');

var u2f = require('./lib/u2f.js');

describe('Node-U2F', function() {

    var appId = "testApp.com";
    var options = {
        timeoutSeconds: 100,
        requestId: 10
    };

    var fakeKeys = [{
        version: "U2F_V2",
        keyHandle: "Ym9ndXNfMTQ2NTk3NjAyMTM3Nw"
    }];

    var tokens = [];
    var tokenMeta = [];

    var fakeMeta = [
        {keyHandle: "test-key-1"},
        {keyHandle: "test-key-2"}
    ];

    before(function() {
        tokens.push(new VirtualToken());
        tokens.push(new VirtualToken());
    });

    it('Generates compliant registration requests', function() {

        var req = u2f.startRegistration(appId, fakeMeta, options)
        .then(function(req) {

            // Check header
            assert.equal(req.appId, appId);
            assert.equal(req.type, 'u2f_register_request');
            
            // Check challenge
            assert.equal(req.registerRequests[0].version, 'U2F_V2');
            assert(typeof req.registerRequests[0].challenge !== 'undefined');

            // Check existing keys
            //assert.equal(req.registeredKeys[0].version, fakeKeys.version);
            assert.equal(req.registeredKeys[0].keyHandle, fakeMeta[0].keyHandle);
            assert.equal(req.registeredKeys[1].keyHandle, fakeMeta[1].keyHandle);

            // Check options
            assert.equal(req.timeoutSeconds, options.timeoutSeconds);
            assert.equal(req.requestId, options.requestId);

        });
    });

    it('Handles registration requests', function(done) {

        var registerRequest = null;

        u2f.startRegistration(appId, [])
        .then(function(req) {

            registerRequest = req;
            return tokens[0].HandleRegisterRequest(req)

        }).then(function(resp) {

            return u2f.finishRegistration(registerRequest, resp);

        }).then(function(result) {

            assert(typeof result.errorCode === 'undefined');

            assert(typeof result.keyHandle !== 'undefined');
            assert(typeof result.publicKey !== 'undefined');

            tokenMeta.push({keyHandle: result.keyHandle, publicKey: result.publicKey});

            done();

        }, done).catch(done);
    });

    it('Generates compliant authentication requests', function() {

        u2f.startAuthentication(appId, tokenMeta, options)
            .then(function(req) {

            // Check header
            assert.equal(req.appId, appId);
            assert.equal(req.type, 'u2f_sign_request');
            assert(typeof req.challenge !== 'undefined');
            
            // Check key handles
            assert.equal(req.registeredKeys[0].keyHandle, tokenMeta[0].keyHandle);
            assert.equal(req.registeredKeys[0].version, 'U2F_V2');

            // Check options
            assert.equal(req.timeoutSeconds, options.timeoutSeconds);
            assert.equal(req.requestId, options.requestId);

        });

    });

    it('Handles authentication requests', function(done) {

        var authRequest = null;
        
        u2f.startAuthentication(appId, tokenMeta)
        .then(function(req) {

            authRequest = req;
            return tokens[0].HandleSignRequest(req);

        }).then(function(resp) {

            return u2f.finishAuthentication(authRequest, resp, tokenMeta);

        }).then(function(result) {

            assert(typeof result.errorCode === 'undefined');
            done();
            
        }, done).catch(done);

    });

    it('Handles multiple registrations', function(done) {

        var registrationReq = null;

        u2f.startRegistration(appId, tokenMeta)
        .then(function(req) {
            registrationReq = req;
            // Check existing keys are included in registration request
            assert.equal(req.registeredKeys[0].keyHandle, tokenMeta[0].keyHandle);
            // Handle the registration request with the new token
            return tokens[1].HandleRegisterRequest(req);

        }).then(function(resp) {
            return u2f.finishRegistration(registrationReq, resp);

        }).then(function(result) {

            // Check result contains required key metadata
            assert(typeof result.keyHandle !== 'undefined');
            assert(typeof result.publicKey !== 'undefined');
            assert(typeof result.certificate !== 'undefined');

            tokenMeta.push({keyHandle: result.keyHandle, publicKey: result.publicKey});

            done();
        }, done).catch(done);
    });

    it('Handles authentication requests with multiple tokens', function(done) {

        var authRequest = null;
        
        u2f.startAuthentication(appId, tokenMeta)
        .then(function(req) {

            authRequest = req;
            return tokens[0].HandleSignRequest(req);

        }).then(function(resp) {

            return u2f.finishAuthentication(authRequest, resp, tokenMeta);

        }).then(function(result) {

            return u2f.startAuthentication(appId, tokenMeta);
        })
        .then(function(req) {

            authRequest = req;
            return tokens[1].HandleSignRequest(req);

        }).then(function(resp) {

            return u2f.finishAuthentication(authRequest, resp, tokenMeta);

        }).then(function(result) {

            assert(typeof result.errorCode === 'undefined');
            done();
            
        }, done).catch(done);

    });

    it('Rejects authentication with unlisted tokens', function(done) {

        var authRequest = null;
        
        u2f.startAuthentication(appId, tokenMeta)
        .then(function(req) {
            authRequest = req;
            return tokens[1].HandleSignRequest(req);

        }).then(function(resp) {
            // Finish authentication missing the used token
            return u2f.finishAuthentication(req, resp, [tokenMeta[0]]);

        }).then(done, function(error) {
            //TODO: check error
            done();
        }).catch(done);
    });

});

