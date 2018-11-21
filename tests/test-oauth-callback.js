const sinon = require('sinon')
const {expect} = require('chai')
const mw = require('../index.js')
const nock = require('nock')

describe('test oauth callback', function() {
    it('should verify arguments', function() {
        try {
            mw.oauthCallback()
            expect.fail('should fail')
        } catch (err) {}
        try {
            mw.oauthCallback({})
            expect.fail('should fail')
        } catch (err) {
            expect(err.message).to.be.equal('Missing clientId in options')
        }
        try {
            mw.oauthCallback({'clientId': 'foo'})
            expect.fail('should fail')
        } catch (err) {
            expect(err.message).to.be.equal('Missing clientSecret in options')
        }
        try {
            mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar'})
            expect.fail('should fail')
        } catch (err) {
            expect(err.message).to.be.equal('Missing redirectUri in options')
        }
        expect(typeof mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz'})).to.be.equal('function')
    })
    it('should call next if not GET', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'POST'
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz'})(req, undefined, fake)
        expect(fake.calledOnce).to.be.true
        
    })
    it('should call next if not callback uri (unspecified, default)', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'GET',
            'originalUrl': '/foo'
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz'})(req, undefined, fake)
        expect(fake.calledOnce).to.be.true
    })
    it('should call next if not callback uri (specified)', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'GET',
            'originalUrl': '/oauth/callback'
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'path': '/callback'})(req, undefined, fake)
        expect(fake.calledOnce).to.be.true
    })
    it('should call next with error if no authcode', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'GET',
            'originalUrl': '/oauth/callback',
            'query': {}
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz'})(req, undefined, fake)
        expect(fake.calledOnce).to.be.true
        expect(fake.firstCall.args[0].message).to.be.equal('Expected authorization code in query string in "code" param')
    })
    it('should call next with error if not code 200', function(done) {
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(500)

        let fake = sinon.spy()
        let req = {
            'method': 'GET',
            'originalUrl': '/oauth/callback',
            'query': {'code': 'authcode1234'}
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz'})(req, undefined, err => {
            expect(err.message).to.be.equal('Non code-200 response from /services/oauth2/token')
            done()
        })
        
    })
    it('should send correct payload', function(done) {
        nock('https://login.salesforce.com', {
            headers: {
              'content-type': 'multipart/form-data'
            }
          }).post('/services/oauth2/token', 'client_id=foo&client_secret=bar&redirect_uri=baz&code=authcode1234&grant_type=authorization_code')
            .reply(200, {
                'key': 'value'
            })

        let req = {
            'method': 'GET',
            'originalUrl': '/oauth/callback',
            'query': {'code': 'authcode1234'}
        }
        let callback = () => {
            expect(req).to.include.key('sfoauth')
            expect(req.sfoauth).to.include.key('payload')
            expect(req.sfoauth.payload.key).to.be.equal('value')
            done()
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback})(req, undefined, (err) => {
            console.log(err)
            done(err)
        })
    })
    it('should use other key in request if specified', function(done) {
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value'
            })

        let req = {
            'method': 'GET',
            'originalUrl': '/oauth/callback',
            'query': {'code': 'authcode1234'}
        }
        let callback = () => {
            expect(req).to.include.key('foo')
            expect(req.foo).to.include.key('payload')
            expect(req.foo.payload.key).to.be.equal('value')
            done()
        }
        mw.oauthCallback({'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'requestKey': 'foo', 'callback': callback})(req, undefined, (err) => {
            console.log(err)
            done(err)
        })
    })
})