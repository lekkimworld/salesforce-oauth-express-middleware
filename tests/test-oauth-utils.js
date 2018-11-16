const sinon = require('sinon')
const {expect} = require('chai')
const oauthutils = require('../oauth-utils.js')
const nock = require('nock')
const nJwt = require('njwt')
const njwk = require('node-jwk')

describe('tests-oauth-utils', function() {
    let request
    beforeEach(function() {
        
    })

    it('calling fetchWellknownConfig should fetch using supplied base_url', function(done) {
        nock('http://foo.com')
                .get('/.well-known/openid-configuration')
                .reply(200, {
                    "issuer": "https://login.salesforce.com",
                    "authorization_endpoint": "https://login.salesforce.com/services/oauth2/authorize",
                    "token_endpoint": "https://login.salesforce.com/services/oauth2/token",
                    "revocation_endpoint": "https://login.salesforce.com/services/oauth2/revoke",
                    "userinfo_endpoint": "https://login.salesforce.com/services/oauth2/userinfo",
                    "jwks_uri": "https://login.salesforce.com/id/keys",
                    "scopes_supported": [
                        "id",
                        "api",
                        "web",
                        "full",
                        "chatter_api",
                        "visualforce",
                        "refresh_token",
                        "openid",
                        "profile",
                        "email",
                        "address",
                        "phone",
                        "offline_access",
                        "custom_permissions",
                        "wave_api",
                        "eclair_api"
                    ],
                    "response_types_supported": [
                        "code",
                        "token",
                        "token id_token"
                    ],
                    "subject_types_supported": [
                        "public"
                    ],
                    "id_token_signing_alg_values_supported": [
                        "RS256"
                    ],
                    "display_values_supported": [
                        "page",
                        "popup",
                        "touch"
                    ],
                    "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "private_key_jwt"
                    ],
                    "claims_supported": [
                        "active",
                        "address",
                        "email",
                        "email_verified",
                        "family_name",
                        "given_name",
                        "is_app_installed",
                        "language",
                        "locale",
                        "name",
                        "nickname",
                        "organization_id",
                        "phone_number",
                        "phone_number_verified",
                        "photos",
                        "picture",
                        "preferred_username",
                        "profile",
                        "sub",
                        "updated_at",
                        "urls",
                        "user_id",
                        "user_type",
                        "zoneinfo"
                    ]
                })
        oauthutils.fetchWellknownConfig('http://foo.com').then(res => {
            expect(typeof res).to.be.equal('object')
            expect(res.display_values_supported.length).to.equal(3)
            done()
        }).catch(err => {
            done(err)
        })

    })

    it('fetchIdentity should load id url with access_token', function(done) {
        nock('http://foo.com')
            .get('/foo')
            .reply(function(uri, requestBody) {
                expect(this.req.headers.authorization[0]).to.be.equal('Bearer foobar')
                return [200, {'foo':'bar'}]
            })
        oauthutils.fetchIdentity('foobar', 'http://foo.com/foo').then(res => {
            expect(res.foo).to.equal('bar')
            done()
        }).catch(err => {
            done(err)
        })
    })

    it('verifyIDToken should verify token', function(done) {
        const keys = require('./privateKeySet.json')
        
        nock('https://login.salesforce.com').get('/id/keys').reply(200, keys)

        const keySet = njwk.JWKSet.fromObject(keys);
        let clientId = '3MVG9HxRZv05HarQkkksvf6_L6PUzn5YiX2ArDEVVm2ucdyrcnWD96azO8yBLzir5Pq_I0fz7I06fZvWeJcik'
        let payload = {
            "aud": clientId,
            "iss": "http://myapp.com/",
            "sub": "users/user1234",
            "scope": ["self","admins"]
        }
        let jwt = nJwt.create(payload, keySet.findKeyById("k2").key.toPrivateKeyPEM(), 'RS256');
        jwt.setHeader("kid", "k2")
        jwt.setClaim("access_token", "foo")
        let idtoken = jwt.compact();
        let iss = jwt.body.iss

        oauthutils.verifyIDToken(idtoken, 'https://login.salesforce.com', clientId).then(res => {
            expect(res.body.iss).to.be.equal(iss)
            expect(res.body.access_token).to.be.equal('foo')
            done()

        }).catch(err => {
            done(err)
        })
    })
})