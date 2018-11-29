const express = require('express')
const mw = require('../index.js')
const session = require('express-session')

const app = express()
app.use(session({ secret: process.env.SESSION_SECRET || 'keyboard cat', cookie: { maxAge: 60000 }}))

app.use(mw.oauthCallback({
    'clientId': process.env.OAUTH_CLIENT_ID,
    'clientSecret': process.env.OAUTH_CLIENT_SECRET,
    'redirectUri': process.env.OAUTH_REDIRECT_URI,
    'callback': (req, res) => {
        // log
        console.log(`Received callback from middleware callback - payload. ${JSON.stringify(req.sfoauth.payload)}`)

        // set data in session
        req.session.payload = req.sfoauth
        req.session.save()
        
        // send redirect
        return res.redirect('/')
    }
}))

app.use(mw.oauthInitiation({
    'clientId': process.env.OAUTH_CLIENT_ID,
    'redirectUri': process.env.OAUTH_REDIRECT_URI,
    'callback': (req) => {
        // save session
        req.session.save()
        
        // log
        console.log('See if we have payload in session')
        if (!req.session || !req.session.payload) {
            // we don't
            console.log('No payload found in session - returning false to initiate dance')
            return false
        }
        console.log('We did - return true to continue middleware chain')
        return true
    }
}))

app.get('/', (req, res, next) => {
    res.send(JSON.stringify(req.session.payload, undefined, 2))
})

app.get('/logout', (req, res, next) => {
    req.session.destroy()
    res.redirect('/')
})

app.listen(process.env.PORT || 3000)