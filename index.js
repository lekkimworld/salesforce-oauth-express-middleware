const fetch = require('node-fetch')
const oauthutils = require('./oauth-utils.js')

module.exports = {
    /**
     * Initiates the OAuth dance with Salesforce if the supplied callback returns a value that 
     * coerces to false. Otherwise just forwards the call along the chain. See below for 
     * options:
     * 
     * - callback - function - if returns a value that coerces to false we initiate the OAuth dance (argument is the request object)
     * - clientId - String - client ID for OAuth initiation - required
     * - redirectUri - String - redirection URI as configured in Salesforce - required
     * - loginUrl - String - Salesforce login URL - defaults to https://login.salesforce.com
     * - prompt - String - any prompt arguments to forward to Salesforce - defaults to 'consent'
     * 
     * @param {Object} opts Options to configure the method
     */
    oauthInitiation: opts => {
        const options = opts || {}
        if (!options.callback) options.callback = () => true
        if (!options.clientId) throw Error('Missing clientId in options')
        if (!options.redirectUri) throw Error('Missing redirectUri in options')
        if (!options.loginUrl) options.loginUrl = 'https://login.salesforce.com'
        if (!options.prompt) options.prompt = 'consent'
        const prompt = options.prompt.replace(/ /g, '%20')

        return (req, res, next) => {
            // see if there is a user object in the sessio
            if (!options.callback(req)) {
                // there is not - initiate authentication
                return res.redirect(`${options.loginUrl}/services/oauth2/authorize?client_id=${options.clientId}&redirect_uri=${options.redirectUri}&response_type=code&prompt=${prompt}`)
            } else {
                // yay
                return next()
            }
        }
    },

    /**
     * Adds an OAuth callback to the middleware chain using the supplied path.
     * 
     * - clientId - String - client ID for OAuth initiation - required
     * - clientSecret - String - client secret for OAuth initiation - required
     * - redirectUri - String - redirection URI as configured in Salesforce - required
     * - callback - Function - called when the callback has successfully verified the OAuth callback (arguments: req, res)
     * - path - String - the path the OAuth callback should run under (defaults to /oauth/callback)
     * - loginUrl - String - Salesforce login URL (defaults to https://login.salesforce.com)
     * - requestKey - String - response locals (res.locals) key to store resulting data in (defaults to 'sfoauth')
     * - verifyIdToken - Boolean - should we verify the signature of the received OpenID Connect id_token if any (defaults to true)
     * 
     * @param {Object} opts Options to configure the method
     */
    oauthCallback: opts => {
        if (!opts || typeof opts !== 'object') throw new Error('Missing options or options is not an object')
        const options = opts || {}
        if (!options.clientId) throw Error('Missing clientId in options')
        if (!options.clientSecret) throw Error('Missing clientSecret in options')
        if (!options.redirectUri) throw Error('Missing redirectUri in options')
        if (!options.loginUrl) options.loginUrl = 'https://login.salesforce.com'
        if (!options.path) options.path = '/oauth/callback'
        if (!options.requestKey) options.requestKey = 'sfoauth'
        if (!options.callback || typeof options.callback !== 'function') options.callback = () => {}
        if (!options.hasOwnProperty("verifyIDToken")) options.verifyIDToken = true

        return (req, res, next) => {
            // state
            let didCallback = false

            // route for oauth callback
            if (req.method !== 'GET' || req.path !== options.path) {
                return next()
            }

            // grab authorization code from query string
            const authcode = req.query.code
            if (!authcode) {
                return next(new Error('Expected authorization code in query string in "code" param'))
            }

            // exchange authcode
            fetch(`${options.loginUrl}/services/oauth2/token`, {
                method: 'POST',
                headers: {
                    'content-type': 'application/x-www-form-urlencoded'
                },
                body: `client_id=${options.clientId}&client_secret=${options.clientSecret}&redirect_uri=${options.redirectUri}&code=${authcode}&grant_type=authorization_code`
            }).then(response => {
                if (response.status !== 200) throw Error('Non code-200 response from /services/oauth2/token')
                return response.json()
            }).then(payload => {
                // add the payload to the request
                res.locals[options.requestKey] = {
                    'payload': payload
                }

                // exit here if no id_token in the payload or if we should not verify it
                if (!payload.id_token || !options.verifyIDToken) {
                    didCallback = true
                    return options.callback(req, res)
                }

                // get idtoken out of payload 
                const idtoken = payload.id_token

                // we need to verify the token before trusting it
                return Promise.all([
                    oauthutils.verifyIDToken(idtoken, options.loginUrl, options.clientId, options.keyIdOverride),
                    oauthutils.fetchIdentity(payload.access_token, payload.id)
                ])

            }).then(data => {
                // abort if done
                if (didCallback) return

                // get data
                const verifyResult = data[0]
                const identity = data[1]
                const payload = res.locals[options.requestKey].payload

                // grab verify result and identity and store
                res.locals[options.requestKey].verifiedIdToken = verifyResult
                res.locals[options.requestKey].identity = identity
                res.locals[options.requestKey].scopes = payload.scope.split(' ')

                // get well known config
                return oauthutils.fetchWellknownConfig(identity.urls && identity.urls.custom_domain ? identity.urls.custom_domain : payload.instance_url)

            }).then(config => {
                // abort if done
                if (didCallback) return

                // store
                res.locals[options.requestKey].wellknown_config = config

                // redirect
                didCallback = true
                return options.callback(req, res)

            }).catch(err => {
                // coming here means that we could not verify the ID token
                return next(err)

            })
        }
    },

    /**
     * Handles signed_request POST data authentication for a Salesforce Canvas application.
     * 
     * - clientSecret - String - the client secret to use when verifying the signed_request - required
     * - canvasPath - String - path to intercept for Canvas authentication (defaults to '/canvas')
     * - callback - Function - called when the signed_request has been verified (arguments: request, response, verifiedSignedRequest)
     * 
     * @param {Object} opts 
     */
    canvasApplicationSignedRequestAuthentication: opts => {
        const options = opts || {}
        if (!options.clientSecret) throw new Error('Missing clientSecret for signed_request verification')
        if (!options.path) options.path = '/canvas'
        if (!options.algorithm) options.algorithm = 'sha256'
        if (!options.callback || typeof options.callback !== 'function') options.callback = () => {}

        return (req, res, next) => {
            // see if post and path matched
            if (req.method !== 'POST' || req.path !== options.path) {
                return next()
            }

            // body coming as text as eval due to stange json from SF
            let body = req.body.toString()
            let payload
            if (body.indexOf('signed_request=') === 0) {
                payload = decodeURIComponent(body.substring(15))
            } else {
                try {
                    let idx1 = body.indexOf("'")
                    let idx2 = body.lastIndexOf("'")
                    payload = body.substring(idx1 + 1, idx2)
                } catch (err) {
                    return next(new Error('Unable to parse signed_request JSON', err))
                }
            }
            if (!payload || typeof payload !== 'string' || payload.indexOf('.') < 0 || payload.split('.').length !== 2) return next(Error('Expected a string as the body payload with a period to separate two strings'))

            try {
                // verify signature
                let obj = oauthutils.verifySignedRequest(payload, options.clientSecret)

                // callback
                try {
                    const rc = options.callback(req, res, obj)
                    if (rc) next();
                    return;

                } catch (err) {
                    next(err);
                }

            } catch (err) {
                next(err)
            }
        }
    }
}