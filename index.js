const FormData = require('form-data')
const fetch = require('node-fetch')
const crypto = require('crypto')
const oauthutils = require('./oauth-utils.js')

module.exports = {
    /**
     * Initiates the OAuth dance with Salesforce if the supplied callback returns a value that 
     * coerces to false. Otherwise just forwards the call along the chain. See below for 
     * options:
     * 
     * - callback - function - if returns a value that coerces to false we initiate the OAuth dance
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

        return (req, res, next) => {
            // see if there is a user object in the sessio
            if (!options.callback(req)) {
                // there is not - initiate authentication
                return res.redirect(`${options.loginUrl}/services/oauth2/authorize?client_id=${options.clientId}&redirect_uri=${options.redirectUri}&response_type=code&prompt=${options.prompt}`)
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
     * - callback - Function - called when the 
     * - path - String - the path the OAuth callback should run under (defaults to /oauth/callback)
     * - loginUrl - String - Salesforce login URL (defaults to https://login.salesforce.com)
     * - requestKey - String - request key to store resulting data in (defaults to 'sfoauth')
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

        return (req, res, next) => {
            // state
            let didCallback = false

            // route for oauth callback
            if (req.method !== 'GET' || req.originalUrl !== CALLBACK_PATH) {
                return next()
            }

            // grab authorization code from query string
            const authcode = req.query.code
            if (!authcode) {
                return next(new Error('Expected authorization code'))
            }

            // exchange authcode
            const formdata = new FormData()
            formdata.append('client_id', options.clientId)
            formdata.append('client_secret', options.clientSecret)
            formdata.append('redirect_uri', options.redirectUri)
            formdata.append('code', authcode)
            formdata.append('grant_type', 'authorization_code')
            fetch(`${options.loginUrl}/services/oauth2/token`, {
                method: 'POST',
                body: formdata
            }).then(response => {
                return response.json()
            }).then(payload => {
                // add the payload to the request
                req[options.requestKey] = {
                    'payload': payload
                }

                // exit here if no id_token in the payload or if we should not verify it
                if (!payload.id_token || !options.verifyIDToken) {
                    didCallback = true
                    return options.callback()
                }

                // get idtoken out of payload 
                const idtoken = payload.id_token

                // we need to verify the token before trusting it
                return Promise.all([oauthutils.verifyIDToken(idtoken, options.loginUrl, options.clientId, options.keyIdOverride), oauthutils.fetchIdentity(payload.access_token, payload.id)])

            }).then(data => {
                // abort if done
                if (didCallback) return

                // get data
                const verifyResult = data[0]
                const identity = data[1]

                // grab verify result and identity and store
                req[options.requestKey].verifiedIdToken = verifyResult
                req[options.requestKey].identity = identity
                req[options.requestKey].scopes = req[options.requestKey].payload.scope.split(' ')
                
                // get well known config
                return fetchWellknownConfig(identity.urls.custom_domain || payload.instance_url)

            }).then(config => {
                // abort if done
                if (didCallback) return

                // store
                req[options.requestKey].wellknown_config = config

                // redirect
                didCallback = true
                return options.callback()

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
     * - callback - Function - called when the signed_request has been verified
     * 
     * @param {Object} opts 
     */
    canvasApplicationSignedRequestAuthentication: opts => {
        if (!opts || typeof opts !== 'object') throw new Error('Missing options or options is not an object')
        const options = opts || {}
        if (!options.clientSecret) throw new Error('Missing clientSecret for signed_request verification')
        if (!options.canvasPath) options.canvasPath = '/canvas'
        if (!options.algorithm) options.algorithm = 'sha256'
        if (!options.callback || typeof options.callback === 'function') options.callback = () => {}

        return (req, res, next) => {
            // see if post and path matched
            if (req.method === 'POST' && req.originalUrl === CANVAS_PATH) {
                // body coming as text as eval due to stange json from SF
                let payload
                try {
                    payload = eval(req.body)
                } catch (err) {
                    return next(new Error('Unable to parse signed_request JSON', err))
                }
                
                // split and get payload
                const payloadParts = payload.signed_request.split('.')
                const signaturePart = payloadParts[0]
                const objPart = payloadParts[1]

                // verify payload signature
                if (options.clientSecret) {
                    // do the verification
                    const ourSignature = Buffer.from(crypto.createHmac(options.algorithm, options.clientSecret).update(objPart).digest()).toString('base64')
                    if (ourSignature !== signaturePart) throw Error('Signature is invalid')
                }

                // get object part and callback
                const obj = JSON.parse(Buffer.from(objPart, 'base64').toString())
                options.callback(req, res, obj)

                // next middleware
                return next()
            }
        }
    }
}
