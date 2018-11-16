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

    it('verifyIDToken should NOT verify token when verifying with other key than signing key', function(done) {
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
        let jwt = nJwt.create(payload, keySet.findKeyById("k1").key.toPrivateKeyPEM(), 'RS256');
        jwt.setHeader("kid", "k2")
        jwt.setClaim("access_token", "foo")
        let idtoken = jwt.compact();

        oauthutils.verifyIDToken(idtoken, 'https://login.salesforce.com', clientId).then(res => {
            done(new Error('Should fail'))

        }).catch(err => {
            done()
        })
    })

    it('should verify input for signed_request verification', function() {
        try {
            oauthutils.verifySignedRequest()
        } catch (err) {
            expect(err.message).to.be.equal('Missing signed_request')
        }
        try {
            oauthutils.verifySignedRequest('foo')
        } catch (err) {
            expect(err.message).to.be.equal('Missing client secret')
        }
        try {
            oauthutils.verifySignedRequest('foo', 'bar')
        } catch (err) {
            expect(err.message).to.be.equal('Signed_request looks malformed - unable to find two parts separated by .')
        }
        try {
            oauthutils.verifySignedRequest('foo.bar', 'bar')
        } catch (err) {
            expect(err.message).to.be.equal('Signature is invalid')
        }
    })

    it('should verify signed_request', function(done) {
        let signed_request = 'Nm43uhqlZxmAeeonPh6OE3uQAZFVj2Jvi42m/HfGQgk=.eyJhbGdvcml0aG0iOiJITUFDU0hBMjU2IiwiaXNzdWVkQXQiOjcyMDM0MzAxNiwidXNlcklkIjoiMDA1MXQwMDAwMDFxalo3QUFJIiwiY2xpZW50Ijp7InJlZnJlc2hUb2tlbiI6bnVsbCwiaW5zdGFuY2VJZCI6Il86SGVyb2tvX0RlbW9fQXBwX0NhbnZhczpjYW52YXMxRmVlZCIsInRhcmdldE9yaWdpbiI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbSIsImluc3RhbmNlVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLm15LnNhbGVzZm9yY2UuY29tIiwib2F1dGhUb2tlbiI6IjAwRDF0MDAwMDAwclh4UiFBUkVBUUZUUGQ0bE5zWFRURnZqeWdWV3hpNklrWnd2aGpnS2tJTnUuSHh2STF4MFY4dm9MNE1Gdm8ucndBdDJ3akRQVGt2VDBhX2FIU1NEeWFZdVY4cDRQTk5YVXZHV0cifSwiY29udGV4dCI6eyJ1c2VyIjp7InVzZXJJZCI6IjAwNTF0MDAwMDAxcWpaN0FBSSIsInVzZXJOYW1lIjoiaWRwcEB0cmFpbGhlYWQuY29tIiwiZmlyc3ROYW1lIjoiTWlra2VsIEZsaW5kdCIsImxhc3ROYW1lIjoiSGVpc3RlcmJlcmciLCJlbWFpbCI6Im1oZWlzdGVyYmVyZ0BzYWxlc2ZvcmNlLmNvbSIsImZ1bGxOYW1lIjoiTWlra2VsIEZsaW5kdCBIZWlzdGVyYmVyZyIsImxvY2FsZSI6ImRhX0RLIiwibGFuZ3VhZ2UiOiJlbl9VUyIsInRpbWVab25lIjoiRXVyb3BlL1BhcmlzIiwicHJvZmlsZUlkIjoiMDBlMXQwMDAwMDFTQnd6Iiwicm9sZUlkIjpudWxsLCJ1c2VyVHlwZSI6IlNUQU5EQVJEIiwiY3VycmVuY3lJU09Db2RlIjoiRVVSIiwicHJvZmlsZVBob3RvVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLS1jLmRvY3VtZW50Zm9yY2UuY29tL3Byb2ZpbGVwaG90by8wMDUvRiIsInByb2ZpbGVUaHVtYm5haWxVcmwiOiJodHRwczovL2lkcHAtZGVtby1kZXYtZWQtLWMuZG9jdW1lbnRmb3JjZS5jb20vcHJvZmlsZXBob3RvLzAwNS9UIiwic2l0ZVVybCI6bnVsbCwic2l0ZVVybFByZWZpeCI6bnVsbCwibmV0d29ya0lkIjpudWxsLCJhY2Nlc3NpYmlsaXR5TW9kZUVuYWJsZWQiOmZhbHNlLCJpc0RlZmF1bHROZXR3b3JrIjp0cnVlfSwibGlua3MiOnsibG9naW5VcmwiOiJodHRwczovL2lkcHAtZGVtby1kZXYtZWQubXkuc2FsZXNmb3JjZS5jb20iLCJlbnRlcnByaXNlVXJsIjoiL3NlcnZpY2VzL1NvYXAvYy80NC4wLzAwRDF0MDAwMDAwclh4UiIsIm1ldGFkYXRhVXJsIjoiL3NlcnZpY2VzL1NvYXAvbS80NC4wLzAwRDF0MDAwMDAwclh4UiIsInBhcnRuZXJVcmwiOiIvc2VydmljZXMvU29hcC91LzQ0LjAvMDBEMXQwMDAwMDByWHhSIiwicmVzdFVybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wLyIsInNvYmplY3RVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9zb2JqZWN0cy8iLCJzZWFyY2hVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9zZWFyY2gvIiwicXVlcnlVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9xdWVyeS8iLCJyZWNlbnRJdGVtc1VybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wL3JlY2VudC8iLCJjaGF0dGVyRmVlZHNVcmwiOiIvc2VydmljZXMvZGF0YS92MzEuMC9jaGF0dGVyL2ZlZWRzIiwiY2hhdHRlckdyb3Vwc1VybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wL2NoYXR0ZXIvZ3JvdXBzIiwiY2hhdHRlclVzZXJzVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvY2hhdHRlci91c2VycyIsImNoYXR0ZXJGZWVkSXRlbXNVcmwiOiIvc2VydmljZXMvZGF0YS92MzEuMC9jaGF0dGVyL2ZlZWQtaXRlbXMiLCJ1c2VyVXJsIjoiLzAwNTF0MDAwMDAxcWpaN0FBSSJ9LCJhcHBsaWNhdGlvbiI6eyJuYW1lIjoiSGVyb2tvIERlbW8gQXBwIChDYW52YXMpIiwiY2FudmFzVXJsIjoiaHR0cHM6Ly9zYWxlc2ZvcmNlLWlkcHAtZGVtby5oZXJva3VhcHAuY29tL2NhbnZhcyIsImFwcGxpY2F0aW9uSWQiOiIwNlAxdDAwMDAwMEhOVVAiLCJ2ZXJzaW9uIjoiMS4wIiwiYXV0aFR5cGUiOiJTSUdORURfUkVRVUVTVCIsInJlZmVyZW5jZUlkIjoiMDlIMXQwMDAwMDBEQXdlIiwib3B0aW9ucyI6W10sInNhbWxJbml0aWF0aW9uTWV0aG9kIjoiTm9uZSIsIm5hbWVzcGFjZSI6IiIsImlzSW5zdGFsbGVkUGVyc29uYWxBcHAiOmZhbHNlLCJkZXZlbG9wZXJOYW1lIjoiSGVyb2tvX0RlbW9fQXBwX0NhbnZhcyJ9LCJlbnZpcm9ubWVudCI6eyJyZWZlcmVyIjpudWxsLCJsb2NhdGlvblVybCI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC5saWdodG5pbmcuZm9yY2UuY29tL29uZS9vbmUuYXBwI2V5SmpiMjF3YjI1bGJuUkVaV1lpT2lKbWIzSmpaVHBqWVc1MllYTkJjSEFpTENKaGRIUnlhV0oxZEdWeklqcDdJbVJsZG1Wc2IzQmxjazVoYldVaU9pSklaWEp2YTI5ZlJHVnRiMTlCY0hCZlEyRnVkbUZ6SWl3aWJtRnRaWE53WVdObFVISmxabWw0SWpvaUlpd2ljR0Z5WVcxbGRHVnljeUk2SW50Y0ltbGtaV0ZKWkZ3aU9pQmNJbUV3TURGME1EQXdNREF5V0hnMFRFRkJVMXdpTENCY0ltTnZiVzFsYm5SSlpGd2lPaUJjSW1OdmJXMWxiblJwWkY4eFhDSjlJaXdpWkdsemNHeGhlVXh2WTJGMGFXOXVJam9pUTJoaGRIUmxja1psWldRaUxDSmpZVzUyWVhOSlpDSTZJbU5oYm5aaGN6RkdaV1ZrSWl3aWNtVmpiM0prU1dRaU9pSXdSRFV4ZERBd01EQXdOMlJGUVhORFFVMGlMQ0p0WVhoSVpXbG5hSFFpT2lKcGJtWnBibWwwWlNJc0ltMWhlRmRwWkhSb0lqb2labWx1WVd3aUxDSm9aV2xuYUhRaU9pSXhNREFsSWl3aWQybGtkR2dpT2lJeE1EQWxJbjBzSW5OMFlYUmxJanA3ZlgwJTNEIiwiZGlzcGxheUxvY2F0aW9uIjoiQ2hhdHRlckZlZWQiLCJzdWJsb2NhdGlvbiI6bnVsbCwidWlUaGVtZSI6IlRoZW1lMyIsImRpbWVuc2lvbnMiOnsid2lkdGgiOiIxMDAlIiwiaGVpZ2h0IjoiMTAwJSIsIm1heFdpZHRoIjoiZmluYWwiLCJtYXhIZWlnaHQiOiJpbmZpbml0ZSIsImNsaWVudFdpZHRoIjoiMTQxNnB4IiwiY2xpZW50SGVpZ2h0IjoiNjUzcHgifSwicGFyYW1ldGVycyI6eyJpZGVhSWQiOiJhMDAxdDAwMDAwMlh4NExBQVMiLCJjb21tZW50SWQiOiJjb21tZW50aWRfMSJ9LCJyZWNvcmQiOnsiYXR0cmlidXRlcyI6eyJ0eXBlIjoiRmVlZEl0ZW0iLCJ1cmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9zb2JqZWN0cy9GZWVkSXRlbS8wRDUxdDAwMDAwN2RFQXNDQU0ifSwiSWQiOiIwRDUxdDAwMDAwN2RFQXNDQU0ifSwidmVyc2lvbiI6eyJzZWFzb24iOiJXSU5URVIiLCJhcGkiOiI0NC4wIn19LCJvcmdhbml6YXRpb24iOnsib3JnYW5pemF0aW9uSWQiOiIwMEQxdDAwMDAwMHJYeFJFQVUiLCJuYW1lIjoiU0ZEQyBFTUVBIiwibXVsdGljdXJyZW5jeUVuYWJsZWQiOmZhbHNlLCJuYW1lc3BhY2VQcmVmaXgiOm51bGwsImN1cnJlbmN5SXNvQ29kZSI6IkVVUiJ9fX0='
        let clientSecret = '6342077776480346444'

        const obj = oauthutils.verifySignedRequest(signed_request, clientSecret)
        expect(typeof obj).to.be.equal('object')
    })

    it('should NOT verify signed_request if secret is wrong', function(done) {
        let signed_request = 'Nm43uhqlZxmAeeonPh6OE3uQAZFVj2Jvi42m/HfGQgk=.eyJhbGdvcml0aG0iOiJITUFDU0hBMjU2IiwiaXNzdWVkQXQiOjcyMDM0MzAxNiwidXNlcklkIjoiMDA1MXQwMDAwMDFxalo3QUFJIiwiY2xpZW50Ijp7InJlZnJlc2hUb2tlbiI6bnVsbCwiaW5zdGFuY2VJZCI6Il86SGVyb2tvX0RlbW9fQXBwX0NhbnZhczpjYW52YXMxRmVlZCIsInRhcmdldE9yaWdpbiI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbSIsImluc3RhbmNlVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLm15LnNhbGVzZm9yY2UuY29tIiwib2F1dGhUb2tlbiI6IjAwRDF0MDAwMDAwclh4UiFBUkVBUUZUUGQ0bE5zWFRURnZqeWdWV3hpNklrWnd2aGpnS2tJTnUuSHh2STF4MFY4dm9MNE1Gdm8ucndBdDJ3akRQVGt2VDBhX2FIU1NEeWFZdVY4cDRQTk5YVXZHV0cifSwiY29udGV4dCI6eyJ1c2VyIjp7InVzZXJJZCI6IjAwNTF0MDAwMDAxcWpaN0FBSSIsInVzZXJOYW1lIjoiaWRwcEB0cmFpbGhlYWQuY29tIiwiZmlyc3ROYW1lIjoiTWlra2VsIEZsaW5kdCIsImxhc3ROYW1lIjoiSGVpc3RlcmJlcmciLCJlbWFpbCI6Im1oZWlzdGVyYmVyZ0BzYWxlc2ZvcmNlLmNvbSIsImZ1bGxOYW1lIjoiTWlra2VsIEZsaW5kdCBIZWlzdGVyYmVyZyIsImxvY2FsZSI6ImRhX0RLIiwibGFuZ3VhZ2UiOiJlbl9VUyIsInRpbWVab25lIjoiRXVyb3BlL1BhcmlzIiwicHJvZmlsZUlkIjoiMDBlMXQwMDAwMDFTQnd6Iiwicm9sZUlkIjpudWxsLCJ1c2VyVHlwZSI6IlNUQU5EQVJEIiwiY3VycmVuY3lJU09Db2RlIjoiRVVSIiwicHJvZmlsZVBob3RvVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLS1jLmRvY3VtZW50Zm9yY2UuY29tL3Byb2ZpbGVwaG90by8wMDUvRiIsInByb2ZpbGVUaHVtYm5haWxVcmwiOiJodHRwczovL2lkcHAtZGVtby1kZXYtZWQtLWMuZG9jdW1lbnRmb3JjZS5jb20vcHJvZmlsZXBob3RvLzAwNS9UIiwic2l0ZVVybCI6bnVsbCwic2l0ZVVybFByZWZpeCI6bnVsbCwibmV0d29ya0lkIjpudWxsLCJhY2Nlc3NpYmlsaXR5TW9kZUVuYWJsZWQiOmZhbHNlLCJpc0RlZmF1bHROZXR3b3JrIjp0cnVlfSwibGlua3MiOnsibG9naW5VcmwiOiJodHRwczovL2lkcHAtZGVtby1kZXYtZWQubXkuc2FsZXNmb3JjZS5jb20iLCJlbnRlcnByaXNlVXJsIjoiL3NlcnZpY2VzL1NvYXAvYy80NC4wLzAwRDF0MDAwMDAwclh4UiIsIm1ldGFkYXRhVXJsIjoiL3NlcnZpY2VzL1NvYXAvbS80NC4wLzAwRDF0MDAwMDAwclh4UiIsInBhcnRuZXJVcmwiOiIvc2VydmljZXMvU29hcC91LzQ0LjAvMDBEMXQwMDAwMDByWHhSIiwicmVzdFVybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wLyIsInNvYmplY3RVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9zb2JqZWN0cy8iLCJzZWFyY2hVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9zZWFyY2gvIiwicXVlcnlVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9xdWVyeS8iLCJyZWNlbnRJdGVtc1VybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wL3JlY2VudC8iLCJjaGF0dGVyRmVlZHNVcmwiOiIvc2VydmljZXMvZGF0YS92MzEuMC9jaGF0dGVyL2ZlZWRzIiwiY2hhdHRlckdyb3Vwc1VybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wL2NoYXR0ZXIvZ3JvdXBzIiwiY2hhdHRlclVzZXJzVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvY2hhdHRlci91c2VycyIsImNoYXR0ZXJGZWVkSXRlbXNVcmwiOiIvc2VydmljZXMvZGF0YS92MzEuMC9jaGF0dGVyL2ZlZWQtaXRlbXMiLCJ1c2VyVXJsIjoiLzAwNTF0MDAwMDAxcWpaN0FBSSJ9LCJhcHBsaWNhdGlvbiI6eyJuYW1lIjoiSGVyb2tvIERlbW8gQXBwIChDYW52YXMpIiwiY2FudmFzVXJsIjoiaHR0cHM6Ly9zYWxlc2ZvcmNlLWlkcHAtZGVtby5oZXJva3VhcHAuY29tL2NhbnZhcyIsImFwcGxpY2F0aW9uSWQiOiIwNlAxdDAwMDAwMEhOVVAiLCJ2ZXJzaW9uIjoiMS4wIiwiYXV0aFR5cGUiOiJTSUdORURfUkVRVUVTVCIsInJlZmVyZW5jZUlkIjoiMDlIMXQwMDAwMDBEQXdlIiwib3B0aW9ucyI6W10sInNhbWxJbml0aWF0aW9uTWV0aG9kIjoiTm9uZSIsIm5hbWVzcGFjZSI6IiIsImlzSW5zdGFsbGVkUGVyc29uYWxBcHAiOmZhbHNlLCJkZXZlbG9wZXJOYW1lIjoiSGVyb2tvX0RlbW9fQXBwX0NhbnZhcyJ9LCJlbnZpcm9ubWVudCI6eyJyZWZlcmVyIjpudWxsLCJsb2NhdGlvblVybCI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC5saWdodG5pbmcuZm9yY2UuY29tL29uZS9vbmUuYXBwI2V5SmpiMjF3YjI1bGJuUkVaV1lpT2lKbWIzSmpaVHBqWVc1MllYTkJjSEFpTENKaGRIUnlhV0oxZEdWeklqcDdJbVJsZG1Wc2IzQmxjazVoYldVaU9pSklaWEp2YTI5ZlJHVnRiMTlCY0hCZlEyRnVkbUZ6SWl3aWJtRnRaWE53WVdObFVISmxabWw0SWpvaUlpd2ljR0Z5WVcxbGRHVnljeUk2SW50Y0ltbGtaV0ZKWkZ3aU9pQmNJbUV3TURGME1EQXdNREF5V0hnMFRFRkJVMXdpTENCY0ltTnZiVzFsYm5SSlpGd2lPaUJjSW1OdmJXMWxiblJwWkY4eFhDSjlJaXdpWkdsemNHeGhlVXh2WTJGMGFXOXVJam9pUTJoaGRIUmxja1psWldRaUxDSmpZVzUyWVhOSlpDSTZJbU5oYm5aaGN6RkdaV1ZrSWl3aWNtVmpiM0prU1dRaU9pSXdSRFV4ZERBd01EQXdOMlJGUVhORFFVMGlMQ0p0WVhoSVpXbG5hSFFpT2lKcGJtWnBibWwwWlNJc0ltMWhlRmRwWkhSb0lqb2labWx1WVd3aUxDSm9aV2xuYUhRaU9pSXhNREFsSWl3aWQybGtkR2dpT2lJeE1EQWxJbjBzSW5OMFlYUmxJanA3ZlgwJTNEIiwiZGlzcGxheUxvY2F0aW9uIjoiQ2hhdHRlckZlZWQiLCJzdWJsb2NhdGlvbiI6bnVsbCwidWlUaGVtZSI6IlRoZW1lMyIsImRpbWVuc2lvbnMiOnsid2lkdGgiOiIxMDAlIiwiaGVpZ2h0IjoiMTAwJSIsIm1heFdpZHRoIjoiZmluYWwiLCJtYXhIZWlnaHQiOiJpbmZpbml0ZSIsImNsaWVudFdpZHRoIjoiMTQxNnB4IiwiY2xpZW50SGVpZ2h0IjoiNjUzcHgifSwicGFyYW1ldGVycyI6eyJpZGVhSWQiOiJhMDAxdDAwMDAwMlh4NExBQVMiLCJjb21tZW50SWQiOiJjb21tZW50aWRfMSJ9LCJyZWNvcmQiOnsiYXR0cmlidXRlcyI6eyJ0eXBlIjoiRmVlZEl0ZW0iLCJ1cmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9zb2JqZWN0cy9GZWVkSXRlbS8wRDUxdDAwMDAwN2RFQXNDQU0ifSwiSWQiOiIwRDUxdDAwMDAwN2RFQXNDQU0ifSwidmVyc2lvbiI6eyJzZWFzb24iOiJXSU5URVIiLCJhcGkiOiI0NC4wIn19LCJvcmdhbml6YXRpb24iOnsib3JnYW5pemF0aW9uSWQiOiIwMEQxdDAwMDAwMHJYeFJFQVUiLCJuYW1lIjoiU0ZEQyBFTUVBIiwibXVsdGljdXJyZW5jeUVuYWJsZWQiOmZhbHNlLCJuYW1lc3BhY2VQcmVmaXgiOm51bGwsImN1cnJlbmN5SXNvQ29kZSI6IkVVUiJ9fX0='
        let clientSecret = 'foo'

        try {
            oauthutils.verifySignedRequest(signed_request, clientSecret)
        } catch (err) {
            expect(err.message).to.be.equal('Signature is invalid')
        }
    })
})