# Golang OAuth 2.0 Example Flow

> This project was created with only purpose for understanding OAuth 2.0 Grant Flows. (DON'T USE IN PRODUCTION).

### How to run!
```bash
docker-compose up
```

## OAuth 2.0 Grant Flows Explained
[More information in OAuth.net](https://oauth.net/2/grant-types/)

### [Authorization Code with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce)

The PKCE-enhanced Authorization Code Flow introduces a secret created by the calling application that can be verified by
the authorization server; this secret is called the Code Verifier. Additionally, the calling app creates a transform 
value of the Code Verifier called the Code Challenge and sends this value over HTTPS to retrieve an Authorization Code. 
This way, a malicious attacker can only intercept the Authorization Code, and they cannot exchange it for a token 
without the Code Verifier.

You can test here: http://localhost:9094/code

![authorization_code_flow](https://images.ctfassets.net/cdy7uua7fh8z/3pstjSYx3YNSiJQnwKZvm5/33c941faf2e0c434a9ab1f0f3a06e13a/auth-sequence-auth-code-pkce.png)

### [Client Credentials](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow)
Great for flow machine-to-machine (M2M) applications, such as CLIs, daemons, or services running on your back-end, the
system authenticates and authorizes the app rather than a user. M2M apps use the Client Credentials Flow, in which they 
pass along their Client ID and Client Secret to authenticate themselves and get a token.

You can test here: http://localhost:9094/client-credentials

![client_credentials_flow](https://images.ctfassets.net/cdy7uua7fh8z/2waLvaQdM5Fl5ZN5xUrF2F/8c5ddae68ac8dd438cdeb91fe1010fd1/auth-sequence-client-credentials.png)

### [Password Credentials](https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow)
The Password grant type is a way to exchange a user's credentials for an access token. Because the client application 
has to collect the user's password and send it to the authorization server, it is not recommended that this grant be 
used at all anymore. **(DEPRECATED, It's considered a Legacy Flow)**

You can test here: http://localhost:9094/pwd-credentials

![password_credentials_flow](https://images.ctfassets.net/cdy7uua7fh8z/4EeYNcnVX1RFcTy5z4lP4v/c3e4d22e6f8bf558caf07338a7388097/ROP_Grant.png)

### [Refresh Token](https://www.oauth.com/oauth2-servers/access-tokens/refreshing-access-tokens/)
An OAuth Refresh Token is a string that the OAuth client can use to get a new access token without the user's interaction.

You can test here: http://localhost:9094/refresh

```text
POST /oauth/token HTTP/1.1
Host: localhost:9094
 
grant_type=refresh_token
&refresh_token=xxxxxxxxxxx
&client_id=xxxxxxxxxx
&client_secret=xxxxxxxxxx
```