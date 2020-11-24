const sinon = require('sinon')
const { expect } = require('chai')
const mw = require('../index.js')
const nock = require('nock')
const mockrequire = require('proxyquire')

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
            mw.oauthCallback({ 'clientId': 'foo' })
            expect.fail('should fail')
        } catch (err) {
            expect(err.message).to.be.equal('Missing clientSecret in options')
        }
        try {
            mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar' })
            expect.fail('should fail')
        } catch (err) {
            expect(err.message).to.be.equal('Missing redirectUri in options')
        }
        expect(typeof mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz' })).to.be.equal('function')
    })
    it('should call next if not GET', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'POST'
        }
        let res = {
            locals: {}
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz' })(req, res, fake)
        expect(fake.calledOnce).to.be.true

    })
    it('should call next if not callback uri (unspecified, default)', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'GET',
            'path': '/foo'
        }
        let res = {
            locals: {}
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz' })(req, res, fake)
        expect(fake.calledOnce).to.be.true
    })
    it('should call next if not callback uri (specified)', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'GET',
            'path': '/oauth/callback'
        }
        let res = {
            locals: {}
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'path': '/callback' })(req, res, fake)
        expect(fake.calledOnce).to.be.true
    })
    it('should call next with error if no authcode', function() {
        let fake = sinon.fake()
        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': {}
        }
        let res = {
            locals: {}
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz' })(req, res, fake)
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
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz' })(req, res, err => {
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
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            expect(res.locals).to.include.key('sfoauth')
            expect(res.locals.sfoauth).to.include.key('payload')
            expect(res.locals.sfoauth.payload.key).to.be.equal('value')
            done()
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
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
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            expect(res.locals).to.include.key('foo')
            expect(res.locals.foo).to.include.key('payload')
            expect(res.locals.foo.payload.key).to.be.equal('value')
            done()
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'requestKey': 'foo', 'callback': callback })(req, res, (err) => {
            console.log(err)
            done(err)
        })
    })

    it('even though there is an id_token it should not be verified if asked not to', function(done) {
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            expect(res.locals.sfoauth.payload.id_token).to.be.equal('dummy')
            done()
        }
        mw.oauthCallback({ 'verifyIDToken': false, 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            console.log(err)
            done(err)
        })
    })

    it('should throw error if id_token cannot be verified', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                verifyIDToken: function(idtoken, loginUrl, clientId, keyIdOverride) {
                    return Promise.reject(Error('Expected to reject'))
                }
            }
        })

        // mock request to token endpoint
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            done(Error('Should not call callback'))
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            expect(err.message).to.be.equal('Expected to reject')
            done()
        })
    })

    it('should throw error if id_token cannot be verified', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                verifyIDToken: function(idtoken, loginUrl, clientId, keyIdOverride) {
                    expect(idtoken).to.be.equal('dummy')
                    expect(loginUrl).to.be.equal('https://foo.example.com')
                    expect(clientId).to.be.equal('someclientid')
                    return Promise.reject(Error('Expected to reject'))
                }
            }
        })

        // mock request to token endpoint
        nock('https://foo.example.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            done(Error('Should not call callback'))
        }
        mw.oauthCallback({ 'clientId': 'someclientid', 'clientSecret': 'bar', 'loginUrl': 'https://foo.example.com', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            expect(err.message).to.be.equal('Expected to reject')
            done()
        })
    })

    it('should throw error if unable to fetch identity', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                fetchIdentity: function(access_token, id) {
                    expect(access_token).to.be.equal('11111')
                    expect(id).to.be.equal('22222')
                    return Promise.reject(Error('Expected to reject'))
                }
            }
        })

        // mock request to token endpoint
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy',
                'access_token': '11111',
                'id': '22222'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            done(Error('Should not call callback'))
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            expect(err.message).to.be.equal('Expected to reject')
            done()
        })
    })

    it('should throw error if unable to get well known config (using custom domain from identity response)', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                verifyIDToken: () => {
                    return Promise.resolve({})
                },
                fetchIdentity: (access_token, id) => {
                    return Promise.resolve({
                        'urls': {
                            'custom_domain': 'urls.custom_domain'
                        }
                    })
                },
                fetchWellknownConfig: (url) => {
                    expect(url).to.be.equal('urls.custom_domain')
                    return Promise.reject(Error('Expected to reject'))
                }
            }
        })

        // mock request to token endpoint
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy',
                'scope': 'foo bar'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            done(Error('Should not call callback'))
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            expect(err.message).to.be.equal('Expected to reject')
            done()
        })
    })

    it('should throw error if unable to get well known config (using instance url if no custom url in identity response)', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                verifyIDToken: () => {
                    return Promise.resolve({})
                },
                fetchIdentity: (access_token, id) => {
                    return Promise.resolve({})
                },
                fetchWellknownConfig: (url) => {
                    expect(url).to.be.equal('my_instance_url')
                    return Promise.reject(Error('Expected to reject'))
                }
            }
        })

        // mock request to token endpoint
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy',
                'scope': 'foo bar',
                'instance_url': 'my_instance_url'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            done(Error('Should not call callback'))
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            expect(err.message).to.be.equal('Expected to reject')
            done()
        })
    })

    it('should set keys correctly in response object if all okay (default requestKey)', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                verifyIDToken: () => {
                    return Promise.resolve({ 'foo': 'foo' })
                },
                fetchIdentity: (access_token, id) => {
                    return Promise.resolve({ 'bar': 'bar' })
                },
                fetchWellknownConfig: (url) => {
                    return Promise.resolve({ 'baz': 'baz' })
                }
            }
        })

        // mock request to token endpoint
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy',
                'scope': 'foo bar',
                'instance_url': 'my_instance_url'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            expect(res.locals.sfoauth.scopes).to.deep.equal(['foo', 'bar'])
            expect(res.locals.sfoauth.verifiedIdToken.foo).to.equal('foo')
            expect(res.locals.sfoauth.identity.bar).to.equal('bar')
            expect(res.locals.sfoauth.wellknown_config.baz).to.equal('baz')
            done()
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'callback': callback })(req, res, (err) => {
            done(err)
        })
    })

    it('should set keys correctly in response object if all okay (supplied requestKey)', function(done) {
        // mock index.js require to override oauth utils
        let mw = mockrequire('../index.js', {
            './oauth-utils.js': {
                verifyIDToken: () => {
                    return Promise.resolve({ 'foo': 'foo' })
                },
                fetchIdentity: (access_token, id) => {
                    return Promise.resolve({ 'bar': 'bar' })
                },
                fetchWellknownConfig: (url) => {
                    return Promise.resolve({ 'baz': 'baz' })
                }
            }
        })

        // mock request to token endpoint
        nock('https://login.salesforce.com')
            .post('/services/oauth2/token')
            .reply(200, {
                'key': 'value',
                'id_token': 'dummy',
                'scope': 'foo bar',
                'instance_url': 'my_instance_url'
            })

        let req = {
            'method': 'GET',
            'path': '/oauth/callback',
            'query': { 'code': 'authcode1234' }
        }
        let res = {
            locals: {}
        }
        let callback = () => {
            expect(res.locals.example.scopes).to.deep.equal(['foo', 'bar'])
            expect(res.locals.example.verifiedIdToken.foo).to.equal('foo')
            expect(res.locals.example.identity.bar).to.equal('bar')
            expect(res.locals.example.wellknown_config.baz).to.equal('baz')
            done()
        }
        mw.oauthCallback({ 'clientId': 'foo', 'clientSecret': 'bar', 'redirectUri': 'baz', 'requestKey': 'example', 'callback': callback })(req, res, (err) => {
            done(err)
        })
    })
})