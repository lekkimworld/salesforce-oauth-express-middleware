const express = require('express')
const mw = require('../index.js')
const session = require('express-session')
const bodyParser = require('body-parser')

// configure app with session support
const app = express()
app.use(bodyParser.raw({
    'type': (req) => {
        let rc = req.path === '/canvas' && req.method === 'POST'
        return rc
    }
}))
app.use(session({ secret: process.env.SESSION_SECRET || 'keyboard cat', cookie: { maxAge: 60000 }}))

// configure canvas app
app.use(mw.canvasApplicationSignedRequestAuthentication({
    "clientSecret": process.env.CANVAS_CLIENT_SECRET,
    //"canvasPath": "/canvas",
    "callback": (req, res, verifiedSignedRequest) => {
        req.session.payload = verifiedSignedRequest
        res.redirect('/')
    }
}))


// just show our payload data
app.get('/', (req, res, next) => {
    // ensure authenticated
    if (!req.session || !req.session.payload) return res.status(401).send('Please access as a Salesforce Canvas app')

    // send response
    res.set("content-type", "application/json")
    res.send(JSON.stringify(req.session.payload, undefined, 2))
})

// allow user to logout
app.get('/logout', (req, res, next) => {
    req.session.destroy()
    res.redirect('/')
})

// listen
app.listen(process.env.PORT || 3000)