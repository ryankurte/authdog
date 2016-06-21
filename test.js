'use strict';

var assert = require('assert');
var VirtualToken = require('virtual-u2f');

var u2f = require('./lib/u2f.js');


describe('Node-U2F', function() {

    var appId = "testApp.com";

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

    it('Handles registration requests', function(done) {

        var req = u2f.startRegistration(appId, registeredKeys);

        var response = null;

        token.HandleRegisterRequest({
            appId: req.appId, 
            type: 'u2f_register_request',
            registerRequests: [{
                version: req.version,
                challenge: req.challenge
            }],
            registeredKeys: []
        })
        .then(function(resp) {

            result = u2f.finishRegistration(req, resp);

            assert(typeof result.errorCode === 'undefined');

            keyHandle = result.keyHandle;
            publicKey = result.publicKey;

            done();
        }, done).catch(done);
    });

    it('Handles signing requests', function(done) {

        var req = u2f.startAuthentication(appId, keyHandle);
        var response = null;

        var resp = token.HandleSignRequest({
            appId: req.appId, 
            type: 'u2f_sign_request',
            challenge: req.challenge,
            registeredKeys: [{
                version: req.version,
                keyHandle: keyHandle
            }]
        })
        .then(function(resp) {

            assert(typeof resp.errorCode == 'undefined');

            result =  u2f.finishAuthentication(req, resp, publicKey);

            assert(typeof result.errorCode === 'undefined');

            done();
        }, done).catch(done);

    });

});

