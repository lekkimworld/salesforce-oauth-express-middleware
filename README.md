# salesforce-oauth-express-middleware
Express middleware to handle OAuth dance initiation, callback, OpenID Connect id_token verification and Canvas signed_request verification.

# OAuth #
OAuth dance initiation and callback is handled using the `oauthInitiation` and `oauthCallback` methods. See the `oauth-test-app` for an example of how to use.

# Salesforce Canvas #
To use a node.js app as a Salesforce Canvas application you configure a Connected App in Salesforce using the Canvas configuration section. The app works by Salesforce POSTing a `signed_request` to the app and the app may verify the signed payload using the client secret from the Connected App. See the `canvas-test-app` for an example.

# Deploying the test applications to Heroku #
There a few steps required to run the apps on Heroku. 
1. Edit the Procfile to indicate the app to run (i.e. `web: npm start --prefix canvas-test-app` to run the canvas-test-app)
2. Edit the package.json in the root directory to indicate the app to run in the postinstall script (i.e. `"postinstall": "npm install --prefix canvas-test-app"` for the canvas-test-app) 
3. Commit and push to Heroku setting the required environment variables as well. Below is a complete example for the canvas-test-app.

```
$ heroku apps:create --region eu
$ heroku config:set CANVAS_CLIENT_SECRET=1234567890
$ git push heroku master
```
