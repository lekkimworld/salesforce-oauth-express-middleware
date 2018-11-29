const sinon = require('sinon')
const {expect} = require('chai')
const mw = require('../index.js')
const mockrequire = require('proxyquire')

describe('tests-index oauthInitiation', function() {
    it('should return a function', function() {
        expect(typeof mw.canvasApplicationSignedRequestAuthentication).to.be.equal('function')
    })
    it('should verify the arguments', function() {
        try {
            mw.canvasApplicationSignedRequestAuthentication()
        } catch (err) {
            expect(err.message).to.be.equal('Missing clientSecret for signed_request verification')
        }
        mw.canvasApplicationSignedRequestAuthentication({ clientSecret: 'bar' })
    })
    it('should call next if not POST', function(done) {
        const req = {
            'method': 'GET'
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo' })(req, undefined, () => {
            done()
        })
    })
    it('should call next if not right path (default)', function(done) {
        const req = {
            'method': 'GET',
            'originalUrl': '/foo'
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo' })(req, undefined, () => {
            done()
        })
    })
    it('should call next if not right path (specified)', function(done) {
        const req = {
            'method': 'GET',
            'originalUrl': '/canvas'
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo', 'path': '/foo' })(req, undefined, () => {
            done()
        })
    })
    it('should call next with error if unable to parse body', function(done) {
        const req = {
            'method': 'POST',
            'originalUrl': '/canvas',
            'body': "{'f:9}"
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo' })(req, undefined, (err) => {
            expect(err.message).to.be.equal('Unable to parse signed_request JSON')
            done()
        })
    })
    it('should call next with error if verifySignedRequest throws an error', function(done) {
        let mw = mockrequire('../index.js', {'./oauth-utils.js': {
            verifySignedRequest: (payload, clientSecret) => {
                expect(payload.foo).to.be.equal('bar')
                expect(clientSecret).to.be.equal('mysecret')
                throw Error('Unable to verify signed request')
            }
        }})
        const req = {
            'method': 'POST',
            'originalUrl': '/canvas',
            'body': {'foo': 'bar'}
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret' })(req, undefined, (err) => {
            expect(err.message).to.be.equal('Unable to verify signed request')
            done()
        })
    })
    it('should include verified signed request when calling callback', function(done) {
        let mw = mockrequire('../index.js', {'./oauth-utils.js': {
            verifySignedRequest: (payload, clientSecret) => {
                return {'baz': '123'}
            }
        }})
        const req = {
            'method': 'POST',
            'originalUrl': '/canvas',
            'body': {'foo': 'bar'}
        }
        const res = {
            'foo': 'bar'
        }
        const callback = (req, res, obj) => {
            expect(req.method).to.be.equal('POST')
            expect(res.foo).to.be.equal('bar')
            expect(obj.baz).to.be.equal('123')
            done()
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret', 'callback': callback })(req, res, (err) => {
            done(err)
        })
    })
})