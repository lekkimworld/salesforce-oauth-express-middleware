const nJwt = require('njwt')
const njwk = require('node-jwk')
const fetch = require('node-fetch')
const crypto = require('crypto')

/**
 * Method to verify the ID Token we received from Salesforce using the standard 
 * public keys provided by Salesforce.
 * 
 * @param {String} idtoken 
 * @param {String} loginUrl
 * @param {String} clientId 
 */
const verifyIDToken = (idtoken, loginUrl, clientId) => {
    return new Promise((resolve, reject) => {
        // get keys from Salesforce
        fetch(`${loginUrl}/id/keys`).then(res => {
            return res.json()
        }).then(keys => {
            // parse jwk keys
            const myKeySet = njwk.JWKSet.fromObject(keys)

            // get header
            const idtoken_parts = idtoken.split('.')

            // parse header
            const header = JSON.parse(Buffer.from(idtoken_parts[0], 'base64').toString('utf8'))
            if (!header.kid || header.typ !== 'JWT' || header.alg !== 'RS256') return reject(Error('Missing kid in header or invalid type or algorithm'))

            // get key to use
            const jwkKey = myKeySet.findKeyById(header.kid)
            if (!jwkKey) throw Error(`Unable to find key for kid ${header.kid}`)
            return jwkKey.key.toPublicKeyPEM()

        }).then(pem => {
            // verify signature
            const verifyResult = nJwt.verify(idtoken, pem, 'RS256')

            // coming here means we verified the signature - now let's check that we 
            // are the audience meaning it was generated for us
            if (verifyResult.body.aud !== clientId) {
                // it wasn't
                return reject(Error('Received JWT wasn\'t generated for us do we wont accept it!'))
            }

            // we verified the token
            resolve(verifyResult)

        }).catch(err => {
            return reject(err)
        })
    })
}

/**
 * Method to get the identity of a user based on an access_token and id URL.
 * 
 * @param {String} access_token 
 * @param {String} id 
 */
const fetchIdentity = (access_token, id) => {
    return fetch(id, {
        headers: {
            'Authorization': `Bearer ${access_token}`
        }
    }).then(res => res.json())
}

/**
 * Load well-known config from base_url
 * @param {*} base_url 
 */
const fetchWellknownConfig = base_url => {
    return fetch(`${base_url}/.well-known/openid-configuration`).then(res => {
        return res.json()
    })
}

/**
 * Verify signed_request POST data from Salesforce Canvas app.
 * 
 * @param {String} signed_request Signed request - should be a string with two parts separated with .
 * @param {String} clientSecret Client secret used to verify the signed request
 * @param {String} algorithm Algorithm used to verify signed request (defaults to 'sha256')
 */
const verifySignedRequest = (signed_request, clientSecret, algorithm='sha256') => {
    if (!signed_request) throw Error('Missing signed_request')
    if (!clientSecret) throw Error('Missing client secret')

    // split and get payload
    const payloadParts = signed_request.split('.')
    if (payloadParts.length !== 2) throw Error('Signed_request looks malformed - unable to find two parts separated by .')
    const signaturePart = payloadParts[0]
    const objPart = payloadParts[1]

    // verify payload signature
    const ourSignature = Buffer.from(crypto.createHmac(algorithm, clientSecret).update(objPart).digest()).toString('base64')
    if (ourSignature !== signaturePart) throw Error('Signature is invalid')

    // get object part and callback
    const obj = JSON.parse(Buffer.from(objPart, 'base64').toString())
    return obj
}

module.exports = {
    verifyIDToken,
    fetchIdentity,
    fetchWellknownConfig,
    verifySignedRequest
}