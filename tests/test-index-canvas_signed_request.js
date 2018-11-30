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
            'path': '/foo'
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo' })(req, undefined, () => {
            done()
        })
    })
    it('should call next if not right path (specified)', function(done) {
        const req = {
            'method': 'GET',
            'path': '/canvas'
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo', 'path': '/foo' })(req, undefined, () => {
            done()
        })
    })
    it('should call next with error if unable to parse body', function(done) {
        const req = {
            'method': 'POST',
            'path': '/canvas',
            'body': "{'f:9}"
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'foo' })(req, undefined, (err) => {
            expect(err.message).to.be.equal('Expected a string as the body payload with a period to separate two strings')
            done()
        })
    })
    it('should call next with error if payload is not an object', function(done) {
        const req = {
            'method': 'POST',
            'path': '/canvas',
            'body': '"foobar"'
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret' })(req, undefined, (err) => {
            expect(err.message).to.be.equal('Expected a string as the body payload with a period to separate two strings')
            done()
        })
    })
    it('should call next with error if payload has no signed_request key', function(done) {
        const req = {
            'method': 'POST',
            'path': '/canvas',
            'body': {'foo': 'bar'}
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret' })(req, undefined, (err) => {
            expect(err.message).to.be.equal('Expected a string as the body payload with a period to separate two strings')
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
            'path': '/canvas',
            'body': {'signed_request': 'bar'}
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret' })(req, undefined, (err) => {
            expect(err.message).to.not.be.undefined
            done()
        })
    })
    it('should include verified signed request when calling callback', function(done) {
        let mw = mockrequire('../index.js', {'./oauth-utils.js': {
            verifySignedRequest: (payload, clientSecret) => {
                expect(payload).to.be.equal('foo.bar')
                return {'baz': '123'}
            }
        }})
        const req = {
            'method': 'POST',
            'path': '/canvas',
            'body': `signed_request=foo.bar`
        }
        const res = {
            'foo': 'bar'
        }
        const callback = (req, res, obj) => {
            expect(req.method).to.be.equal('POST')
            expect(obj.baz).to.be.equal('123')
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret', 'callback': callback })(req, res, (err) => {
            done(err)
        })
    })
    it('test with actual string payload', function(done) {
        let mw = mockrequire('../index.js', {'./oauth-utils.js': {
            verifySignedRequest: (payload, clientSecret) => {
                expect(payload).to.be.equal("vk8+LPZp2PlXreYxnvbAzRio7+tDCV61Bo2TBgPVN0k=.eyJhbGdvcml0aG0iOiJITUFDU0hBMjU2IiwiaXNzdWVkQXQiOjE2NzYzNzY0MDYsInVzZXJJZCI6IjAwNTF0MDAwMDAxcWpaN0FBSSIsImNsaWVudCI6eyJyZWZyZXNoVG9rZW4iOm51bGwsImluc3RhbmNlSWQiOiJfOlRlc3RfQ2FudmFzX0FwcDoiLCJ0YXJnZXRPcmlnaW4iOiJodHRwczovL2lkcHAtZGVtby1kZXYtZWQubXkuc2FsZXNmb3JjZS5jb20iLCJpbnN0YW5jZVVybCI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbSIsIm9hdXRoVG9rZW4iOiIwMEQxdDAwMDAwMHJYeFIhQVJFQVFESVJvRjNXcmw4RWsueEJYZEVGUjNHbmFRdkUuWlpIYmNkU1o5NlZFVkNHcFROOXdUcHh5RzlvcE1GQkZ2S3hfQzN0WkVSbmV0aHNSZzZXMG02UXRnUVJQODJzIn0sImNvbnRleHQiOnsidXNlciI6eyJ1c2VySWQiOiIwMDUxdDAwMDAwMXFqWjdBQUkiLCJ1c2VyTmFtZSI6ImlkcHBAdHJhaWxoZWFkLmNvbSIsImZpcnN0TmFtZSI6Ik1pa2tlbCBGbGluZHQiLCJsYXN0TmFtZSI6IkhlaXN0ZXJiZXJnIiwiZW1haWwiOiJtaGVpc3RlcmJlcmdAc2FsZXNmb3JjZS5jb20iLCJmdWxsTmFtZSI6Ik1pa2tlbCBGbGluZHQgSGVpc3RlcmJlcmciLCJsb2NhbGUiOiJkYV9ESyIsImxhbmd1YWdlIjoiZW5fVVMiLCJ0aW1lWm9uZSI6IkV1cm9wZS9QYXJpcyIsInByb2ZpbGVJZCI6IjAwZTF0MDAwMDAxU0J3eiIsInJvbGVJZCI6bnVsbCwidXNlclR5cGUiOiJTVEFOREFSRCIsImN1cnJlbmN5SVNPQ29kZSI6IkVVUiIsInByb2ZpbGVQaG90b1VybCI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC0tYy5kb2N1bWVudGZvcmNlLmNvbS9wcm9maWxlcGhvdG8vMDA1L0YiLCJwcm9maWxlVGh1bWJuYWlsVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLS1jLmRvY3VtZW50Zm9yY2UuY29tL3Byb2ZpbGVwaG90by8wMDUvVCIsInNpdGVVcmwiOm51bGwsInNpdGVVcmxQcmVmaXgiOm51bGwsIm5ldHdvcmtJZCI6bnVsbCwiYWNjZXNzaWJpbGl0eU1vZGVFbmFibGVkIjpmYWxzZSwiaXNEZWZhdWx0TmV0d29yayI6dHJ1ZX0sImxpbmtzIjp7ImxvZ2luVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLm15LnNhbGVzZm9yY2UuY29tIiwiZW50ZXJwcmlzZVVybCI6Ii9zZXJ2aWNlcy9Tb2FwL2MvNDQuMC8wMEQxdDAwMDAwMHJYeFIiLCJtZXRhZGF0YVVybCI6Ii9zZXJ2aWNlcy9Tb2FwL20vNDQuMC8wMEQxdDAwMDAwMHJYeFIiLCJwYXJ0bmVyVXJsIjoiL3NlcnZpY2VzL1NvYXAvdS80NC4wLzAwRDF0MDAwMDAwclh4UiIsInJlc3RVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC8iLCJzb2JqZWN0VXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvc29iamVjdHMvIiwic2VhcmNoVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvc2VhcmNoLyIsInF1ZXJ5VXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvcXVlcnkvIiwicmVjZW50SXRlbXNVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9yZWNlbnQvIiwiY2hhdHRlckZlZWRzVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjMxLjAvY2hhdHRlci9mZWVkcyIsImNoYXR0ZXJHcm91cHNVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9jaGF0dGVyL2dyb3VwcyIsImNoYXR0ZXJVc2Vyc1VybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wL2NoYXR0ZXIvdXNlcnMiLCJjaGF0dGVyRmVlZEl0ZW1zVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjMxLjAvY2hhdHRlci9mZWVkLWl0ZW1zIiwidXNlclVybCI6Ii8wMDUxdDAwMDAwMXFqWjdBQUkifSwiYXBwbGljYXRpb24iOnsibmFtZSI6IlRlc3QgQ2FudmFzIEFwcCIsImNhbnZhc1VybCI6Imh0dHBzOi8vc2xlZXB5LWdhcmRlbi00NTAxNC5oZXJva3VhcHAuY29tL2NhbnZhcyIsImFwcGxpY2F0aW9uSWQiOiIwNlAxdDAwMDAwMEhTeFQiLCJ2ZXJzaW9uIjoiMS4wIiwiYXV0aFR5cGUiOiJTSUdORURfUkVRVUVTVCIsInJlZmVyZW5jZUlkIjoiMDlIMXQwMDAwMDBER01ZIiwib3B0aW9ucyI6W10sInNhbWxJbml0aWF0aW9uTWV0aG9kIjoiTm9uZSIsImlzSW5zdGFsbGVkUGVyc29uYWxBcHAiOmZhbHNlLCJuYW1lc3BhY2UiOiIiLCJkZXZlbG9wZXJOYW1lIjoiVGVzdF9DYW52YXNfQXBwIn0sImVudmlyb25tZW50Ijp7InJlZmVyZXIiOm51bGwsImxvY2F0aW9uVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLm15LnNhbGVzZm9yY2UuY29tL191aS9mb3JjZS9jYW52YXMvdWkvQ2FudmFzUHJldmlld2VyVWk/cmV0VVJMPSUyRnNldHVwJTJGaG9tZSZhcHBMYXlvdXQ9c2V0dXAmdG91cj0maXNkdHA9cDEmc2ZkY0lGcmFtZU9yaWdpbj1odHRwczovL2lkcHAtZGVtby1kZXYtZWQubGlnaHRuaW5nLmZvcmNlLmNvbSZzZmRjSUZyYW1lSG9zdD13ZWImbm9uY2U9NmMyMjc3MDRiZDhlODcwYjYyZWQ5YmNmMDY5YWU4OGJkYzFiZGRmYzIzNjhiY2M1Mzk4YThjM2YzNjk5ZDNiOSZjbGM9MSIsImRpc3BsYXlMb2NhdGlvbiI6bnVsbCwic3VibG9jYXRpb24iOm51bGwsInVpVGhlbWUiOiJUaGVtZTMiLCJkaW1lbnNpb25zIjp7IndpZHRoIjoiODAwcHgiLCJoZWlnaHQiOiI5MDBweCIsIm1heFdpZHRoIjoiMTAwMHB4IiwibWF4SGVpZ2h0IjoiMjAwMHB4IiwiY2xpZW50V2lkdGgiOiIxMjE4cHgiLCJjbGllbnRIZWlnaHQiOiI4MHB4In0sInBhcmFtZXRlcnMiOnt9LCJyZWNvcmQiOnt9LCJ2ZXJzaW9uIjp7InNlYXNvbiI6IldJTlRFUiIsImFwaSI6IjQ0LjAifX0sIm9yZ2FuaXphdGlvbiI6eyJvcmdhbml6YXRpb25JZCI6IjAwRDF0MDAwMDAwclh4UkVBVSIsIm5hbWUiOiJTRkRDIEVNRUEiLCJtdWx0aWN1cnJlbmN5RW5hYmxlZCI6ZmFsc2UsIm5hbWVzcGFjZVByZWZpeCI6bnVsbCwiY3VycmVuY3lJc29Db2RlIjoiRVVSIn19fQ==")
                return {'baz': '123'}
            }
        }})
        const req = {
            'method': 'POST',
            'path': '/canvas',
            'body': `signed_request=vk8+LPZp2PlXreYxnvbAzRio7+tDCV61Bo2TBgPVN0k=.eyJhbGdvcml0aG0iOiJITUFDU0hBMjU2IiwiaXNzdWVkQXQiOjE2NzYzNzY0MDYsInVzZXJJZCI6IjAwNTF0MDAwMDAxcWpaN0FBSSIsImNsaWVudCI6eyJyZWZyZXNoVG9rZW4iOm51bGwsImluc3RhbmNlSWQiOiJfOlRlc3RfQ2FudmFzX0FwcDoiLCJ0YXJnZXRPcmlnaW4iOiJodHRwczovL2lkcHAtZGVtby1kZXYtZWQubXkuc2FsZXNmb3JjZS5jb20iLCJpbnN0YW5jZVVybCI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbSIsIm9hdXRoVG9rZW4iOiIwMEQxdDAwMDAwMHJYeFIhQVJFQVFESVJvRjNXcmw4RWsueEJYZEVGUjNHbmFRdkUuWlpIYmNkU1o5NlZFVkNHcFROOXdUcHh5RzlvcE1GQkZ2S3hfQzN0WkVSbmV0aHNSZzZXMG02UXRnUVJQODJzIn0sImNvbnRleHQiOnsidXNlciI6eyJ1c2VySWQiOiIwMDUxdDAwMDAwMXFqWjdBQUkiLCJ1c2VyTmFtZSI6ImlkcHBAdHJhaWxoZWFkLmNvbSIsImZpcnN0TmFtZSI6Ik1pa2tlbCBGbGluZHQiLCJsYXN0TmFtZSI6IkhlaXN0ZXJiZXJnIiwiZW1haWwiOiJtaGVpc3RlcmJlcmdAc2FsZXNmb3JjZS5jb20iLCJmdWxsTmFtZSI6Ik1pa2tlbCBGbGluZHQgSGVpc3RlcmJlcmciLCJsb2NhbGUiOiJkYV9ESyIsImxhbmd1YWdlIjoiZW5fVVMiLCJ0aW1lWm9uZSI6IkV1cm9wZS9QYXJpcyIsInByb2ZpbGVJZCI6IjAwZTF0MDAwMDAxU0J3eiIsInJvbGVJZCI6bnVsbCwidXNlclR5cGUiOiJTVEFOREFSRCIsImN1cnJlbmN5SVNPQ29kZSI6IkVVUiIsInByb2ZpbGVQaG90b1VybCI6Imh0dHBzOi8vaWRwcC1kZW1vLWRldi1lZC0tYy5kb2N1bWVudGZvcmNlLmNvbS9wcm9maWxlcGhvdG8vMDA1L0YiLCJwcm9maWxlVGh1bWJuYWlsVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLS1jLmRvY3VtZW50Zm9yY2UuY29tL3Byb2ZpbGVwaG90by8wMDUvVCIsInNpdGVVcmwiOm51bGwsInNpdGVVcmxQcmVmaXgiOm51bGwsIm5ldHdvcmtJZCI6bnVsbCwiYWNjZXNzaWJpbGl0eU1vZGVFbmFibGVkIjpmYWxzZSwiaXNEZWZhdWx0TmV0d29yayI6dHJ1ZX0sImxpbmtzIjp7ImxvZ2luVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLm15LnNhbGVzZm9yY2UuY29tIiwiZW50ZXJwcmlzZVVybCI6Ii9zZXJ2aWNlcy9Tb2FwL2MvNDQuMC8wMEQxdDAwMDAwMHJYeFIiLCJtZXRhZGF0YVVybCI6Ii9zZXJ2aWNlcy9Tb2FwL20vNDQuMC8wMEQxdDAwMDAwMHJYeFIiLCJwYXJ0bmVyVXJsIjoiL3NlcnZpY2VzL1NvYXAvdS80NC4wLzAwRDF0MDAwMDAwclh4UiIsInJlc3RVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC8iLCJzb2JqZWN0VXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvc29iamVjdHMvIiwic2VhcmNoVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvc2VhcmNoLyIsInF1ZXJ5VXJsIjoiL3NlcnZpY2VzL2RhdGEvdjQ0LjAvcXVlcnkvIiwicmVjZW50SXRlbXNVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9yZWNlbnQvIiwiY2hhdHRlckZlZWRzVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjMxLjAvY2hhdHRlci9mZWVkcyIsImNoYXR0ZXJHcm91cHNVcmwiOiIvc2VydmljZXMvZGF0YS92NDQuMC9jaGF0dGVyL2dyb3VwcyIsImNoYXR0ZXJVc2Vyc1VybCI6Ii9zZXJ2aWNlcy9kYXRhL3Y0NC4wL2NoYXR0ZXIvdXNlcnMiLCJjaGF0dGVyRmVlZEl0ZW1zVXJsIjoiL3NlcnZpY2VzL2RhdGEvdjMxLjAvY2hhdHRlci9mZWVkLWl0ZW1zIiwidXNlclVybCI6Ii8wMDUxdDAwMDAwMXFqWjdBQUkifSwiYXBwbGljYXRpb24iOnsibmFtZSI6IlRlc3QgQ2FudmFzIEFwcCIsImNhbnZhc1VybCI6Imh0dHBzOi8vc2xlZXB5LWdhcmRlbi00NTAxNC5oZXJva3VhcHAuY29tL2NhbnZhcyIsImFwcGxpY2F0aW9uSWQiOiIwNlAxdDAwMDAwMEhTeFQiLCJ2ZXJzaW9uIjoiMS4wIiwiYXV0aFR5cGUiOiJTSUdORURfUkVRVUVTVCIsInJlZmVyZW5jZUlkIjoiMDlIMXQwMDAwMDBER01ZIiwib3B0aW9ucyI6W10sInNhbWxJbml0aWF0aW9uTWV0aG9kIjoiTm9uZSIsImlzSW5zdGFsbGVkUGVyc29uYWxBcHAiOmZhbHNlLCJuYW1lc3BhY2UiOiIiLCJkZXZlbG9wZXJOYW1lIjoiVGVzdF9DYW52YXNfQXBwIn0sImVudmlyb25tZW50Ijp7InJlZmVyZXIiOm51bGwsImxvY2F0aW9uVXJsIjoiaHR0cHM6Ly9pZHBwLWRlbW8tZGV2LWVkLm15LnNhbGVzZm9yY2UuY29tL191aS9mb3JjZS9jYW52YXMvdWkvQ2FudmFzUHJldmlld2VyVWk/cmV0VVJMPSUyRnNldHVwJTJGaG9tZSZhcHBMYXlvdXQ9c2V0dXAmdG91cj0maXNkdHA9cDEmc2ZkY0lGcmFtZU9yaWdpbj1odHRwczovL2lkcHAtZGVtby1kZXYtZWQubGlnaHRuaW5nLmZvcmNlLmNvbSZzZmRjSUZyYW1lSG9zdD13ZWImbm9uY2U9NmMyMjc3MDRiZDhlODcwYjYyZWQ5YmNmMDY5YWU4OGJkYzFiZGRmYzIzNjhiY2M1Mzk4YThjM2YzNjk5ZDNiOSZjbGM9MSIsImRpc3BsYXlMb2NhdGlvbiI6bnVsbCwic3VibG9jYXRpb24iOm51bGwsInVpVGhlbWUiOiJUaGVtZTMiLCJkaW1lbnNpb25zIjp7IndpZHRoIjoiODAwcHgiLCJoZWlnaHQiOiI5MDBweCIsIm1heFdpZHRoIjoiMTAwMHB4IiwibWF4SGVpZ2h0IjoiMjAwMHB4IiwiY2xpZW50V2lkdGgiOiIxMjE4cHgiLCJjbGllbnRIZWlnaHQiOiI4MHB4In0sInBhcmFtZXRlcnMiOnt9LCJyZWNvcmQiOnt9LCJ2ZXJzaW9uIjp7InNlYXNvbiI6IldJTlRFUiIsImFwaSI6IjQ0LjAifX0sIm9yZ2FuaXphdGlvbiI6eyJvcmdhbml6YXRpb25JZCI6IjAwRDF0MDAwMDAwclh4UkVBVSIsIm5hbWUiOiJTRkRDIEVNRUEiLCJtdWx0aWN1cnJlbmN5RW5hYmxlZCI6ZmFsc2UsIm5hbWVzcGFjZVByZWZpeCI6bnVsbCwiY3VycmVuY3lJc29Db2RlIjoiRVVSIn19fQ==`
        }
        const res = {
            'foo': 'bar'
        }
        const callback = (req, res, obj) => {
            expect(req.method).to.be.equal('POST')
            expect(obj.baz).to.be.equal('123')
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret', 'callback': callback })(req, res, (err) => {
            done(err)
        })
    })
    it('test with actual string payload (urldecode)', function(done) {
        let mw = mockrequire('../index.js', {'./oauth-utils.js': {
            verifySignedRequest: (payload, clientSecret) => {
                expect(payload).to.be.equal("foo=.bar==")
                return {'baz': '123'}
            }
        }})
        const req = {
            'method': 'POST',
            'path': '/canvas',
            'body': 'signed_request=foo%3D.bar%3D%3D'
        }
        const res = {
            'foo': 'bar'
        }
        const callback = (req, res, obj) => {
            expect(req.method).to.be.equal('POST')
            expect(obj.baz).to.be.equal('123')
        }
        mw.canvasApplicationSignedRequestAuthentication({ 'clientSecret': 'mysecret', 'callback': callback })(req, res, (err) => {
            if (err) return done(err)
            done()
        })
    })
})