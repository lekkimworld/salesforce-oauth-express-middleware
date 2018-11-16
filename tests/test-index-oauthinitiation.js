const sinon = require('sinon')
const {expect} = require('chai')
const mw = require('../index.js')

describe('tests-index oauthInitiation', function() {
    it('should return a function', function() {
        expect(typeof mw.oauthInitiation).to.be.equal('function')
    })
    it('should verify the arguments', function() {
        try {
            mw.oauthInitiation()
        } catch (err) {
            expect(err.message).to.be.equal('Missing clientId in options')
        }
        try {
            mw.oauthInitiation({})
        } catch (err) {
            expect(err.message).to.be.equal('Missing clientId in options')
        }
        try {
            mw.oauthInitiation({ clientId: 'foo' })
        } catch (err) {
            expect(err.message).to.be.equal('Missing redirectUri in options')
        }
        mw.oauthInitiation({ clientId: 'bar', redirectUri: 'foo' })
    })
    it('should call next if no callback or it returns true', function() {
        let callback = sinon.fake()
        mw.oauthInitiation({ 'clientId': 'foo', 'redirectUri': 'bar' })(undefined, undefined, callback)
        expect(callback.callCount).to.be.equal(1)

        callback = sinon.fake()
        mw.oauthInitiation({ 'clientId': 'foo', 'redirectUri': 'bar', 'callback': () => true })(undefined, undefined, callback)
        expect(callback.callCount).to.be.equal(1)
    })

    it('should redirect user if callback returns false - minimum', function() {
        let res = {
            'redirect': sinon.fake()
        }
        mw.oauthInitiation({ 'clientId': 'foo', 'redirectUri': 'bar', 'callback': () => false })(undefined, res, undefined)
        expect(res.redirect.callCount).to.be.equal(1)
        expect(res.redirect.firstCall.args[0]).to.be.equal('https://login.salesforce.com/services/oauth2/authorize?client_id=foo&redirect_uri=bar&response_type=code&prompt=consent')
    })

    it('should redirect user if callback returns false - supplied loginUtl', function() {
        let res = {
            'redirect': sinon.fake()
        }
        mw.oauthInitiation({ 'clientId': 'foo', 'redirectUri': 'bar', 'loginUrl': 'https://example.com', 'callback': () => false })(undefined, res, undefined)
        expect(res.redirect.callCount).to.be.equal(1)
        expect(res.redirect.firstCall.args[0]).to.be.equal('https://example.com/services/oauth2/authorize?client_id=foo&redirect_uri=bar&response_type=code&prompt=consent')
    })

    it('should redirect user if callback returns false - supplied prompt', function() {
        let res = {
            'redirect': sinon.fake()
        }
        mw.oauthInitiation({ 'clientId': 'foo', 'redirectUri': 'bar', 'prompt': 'consent foo', 'callback': () => false })(undefined, res, undefined)
        expect(res.redirect.callCount).to.be.equal(1)
        expect(res.redirect.firstCall.args[0]).to.be.equal('https://login.salesforce.com/services/oauth2/authorize?client_id=foo&redirect_uri=bar&response_type=code&prompt=consent%20foo')
    })
})