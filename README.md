# Multifactor Authentication

This app uses H2 to store the user details. JWTs are also used in this app. As described in resource 3, there are 2 'authentication-states'. 
These are AUTHENTICATED and PRE_AUTHENTICATED_MFA_REQUIRED. 

If a user has mfa disabled in the user table (mfa_enabled=false), then a correct login will provide a jwt with an AUTHENTICATED status.

If a user has mfa enabled in the user table (mfa_enabled=true), then a correct login will provide a jwt with a PRE_AUTHENTICATED_MFA_REQUIRED status. This spesific JWT is only valid for 5 minutes. The
mfa endpoint can then be visited to provide the mfa token. If the TOTP check is successful, then a new JWT is issued with a status of AUTHENTICATED. 
    

# Possible future work
Roles/privileges should be added to make this a more complete example.

# API Description

## Authenticate
Do a POST to _localhost:8080/authenticate_  with basic authorization. The usernames are defined in the data.sql file and the
the password for all of these users are "password".

## MFA (if required)
 Do a POST to _localhost:8080/authenticate/mfa_  with the bearer token given when Authentication happened.
 For now the token is attached in json in the format: 
 {
    "mfaCode":123456
  }
 
## Get QR Code to register a device
 Do a GET at _localhost:8080/authenticate/qrcode_  with the bearer token given when Authentication happened.

# Resources
1. https://github.com/samdjstevens/java-totp
2. https://www.baeldung.com/spring-security-two-factor-authentication-with-soft-token
3. https://stackoverflow.com/questions/59918013/multi-factor-authentication-with-spring-boot-2-and-spring-security-5
4. https://medium.com/@ihorsokolyk/two-factor-authentication-with-java-and-google-authenticator-9d7ea15ffee6

