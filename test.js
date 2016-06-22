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

        var req = u2f.startRegistration(appId, fakeMeta, options);

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

    it('Handles registration requests', function(done) {

        var req = u2f.startRegistration(appId, []);

        tokens[0].HandleRegisterRequest(req)
        .then(function(resp) {

            var result = u2f.finishRegistration(req, resp);

            assert(typeof result.errorCode === 'undefined');

            assert(typeof result.keyHandle !== 'undefined');
            assert(typeof result.publicKey !== 'undefined');

            tokenMeta.push({keyHandle: result.keyHandle, publicKey: result.publicKey});

            done();
        }, done).catch(done);
    });

    it('Generates compliant authentication requests', function() {

        var req = u2f.startAuthentication(appId, tokenMeta, options);

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

    it('Handles authentication requests', function(done) {

        var req = u2f.startAuthentication(appId, tokenMeta);

        tokens[0].HandleSignRequest(req)
        .then(function(resp) {

            assert(typeof resp.errorCode == 'undefined');

            var result = u2f.finishAuthentication(req, resp, tokenMeta);

            assert(typeof result.errorCode === 'undefined');

            done();
        }, done).catch(done);

    });

    it('Handles multiple registrations', function(done) {

        var req = u2f.startRegistration(appId, tokenMeta);

        tokens[1].HandleRegisterRequest(req)
        .then(function(resp) {

            var result = u2f.finishRegistration(req, resp);

            assert(typeof result.errorCode === 'undefined');

            assert(typeof result.keyHandle !== 'undefined');
            assert(typeof result.publicKey !== 'undefined');

            tokenMeta.push({keyHandle: result.keyHandle, publicKey: result.publicKey});

            done();
        }, done).catch(done);
    });

    it('Handles authentication requests with multiple tokens', function(done) {

        var req = u2f.startAuthentication(appId, tokenMeta);
        var reqTwo = u2f.startAuthentication(appId, tokenMeta);

        tokens[0].HandleSignRequest(req)
        .then(function(resp) {

            assert(typeof resp.errorCode == 'undefined');

            var result = u2f.finishAuthentication(req, resp, tokenMeta);

            assert(typeof result.errorCode === 'undefined');

            return tokens[1].HandleSignRequest(reqTwo);

        }).then(function(resp) {

            assert(typeof resp.errorCode == 'undefined');

            var result = u2f.finishAuthentication(reqTwo, resp, tokenMeta);

            assert(typeof result.errorCode === 'undefined');

            done();
        }, done).catch(done);
    });

    it('Rejects authentication with unregistered tokens', function(done) {

        var req = u2f.startAuthentication(appId, tokenMeta);

        tokens[1].HandleSignRequest(req)
        .then(function(resp) {

            assert(typeof resp.errorCode == 'undefined');

            var result = u2f.finishAuthentication(req, resp, [tokenMeta[0]]);

            assert(typeof result.errorCode !== 'undefined');

            done();

        }, done).catch(done);
    });

});

