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

    var token = null;
    var keyHandle = null;
    var publicKey = null;

    var registeredKeys = [
        "test-key-1",
        "test-key-2"
    ];

    before(function() {
        token = new VirtualToken();
    });

    it('Generates compliant registration requests', function() {

        var req = u2f.startRegistration(appId, fakeKeys, options);

        // Check header
        assert.equal(req.appId, appId);
        assert.equal(req.type, 'u2f_register_request');
        
        // Check challenge
        assert.equal(req.registerRequests[0].version, 'U2F_V2');
        assert(typeof req.registerRequests[0].challenge !== 'undefined');

        // Check existing keys
        //assert.equal(req.registeredKeys[0].version, fakeKeys.version);
        assert.equal(req.registeredKeys[0].keyHandle, fakeKeys[0].keyHandle);

        // Check options
        assert.equal(req.timeoutSeconds, options.timeoutSeconds);
        assert.equal(req.requestId, options.requestId);
    });

    it('Handles registration requests', function(done) {

        var req = u2f.startRegistration(appId, registeredKeys);

        token.HandleRegisterRequest(req)
        .then(function(resp) {

            var result = u2f.finishRegistration(req, resp);

            assert(typeof result.errorCode === 'undefined');

            assert(typeof result.keyHandle !== 'undefined');
            assert(typeof result.publicKey !== 'undefined');

            keyHandle = result.keyHandle;
            publicKey = result.publicKey;

            done();
        }, done).catch(done);
    });

    it('Generates compliant authentication requests', function() {

        var req = u2f.startAuthentication(appId, [keyHandle], options);

        // Check header
        assert.equal(req.appId, appId);
        assert.equal(req.type, 'u2f_sign_request');
        assert(typeof req.challenge !== 'undefined');
        
        // Check key handles
        assert.equal(req.registeredKeys[0].keyHandle, keyHandle);
        assert.equal(req.registeredKeys[0].version, 'U2F_V2');

        // Check options
        assert.equal(req.timeoutSeconds, options.timeoutSeconds);
        assert.equal(req.requestId, options.requestId);

    });

    it('Handles authentication requests', function(done) {

        var req = u2f.startAuthentication(appId, [keyHandle]);

        token.HandleSignRequest(req)
        .then(function(resp) {

            assert(typeof resp.errorCode == 'undefined');

            var result = u2f.finishAuthentication(req, resp, publicKey);

            assert(typeof result.errorCode === 'undefined');

            done();
        }, done).catch(done);

    });

});

