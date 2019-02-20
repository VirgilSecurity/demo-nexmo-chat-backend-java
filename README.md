# Sample Java Backend for Nexmo

This repository contains a sample backend code that demonstrates how to generate a Nexmo and Virgil JWTs using the [Java/Android SDK](https://github.com/VirgilSecurity/virgil-sdk-java-android)

> Do not use this authentication in production. Requests to a /virgil-jwt endpoint must be allowed for authenticated users. Use your application authorization strategy.

## Prerequisites
* Java Development Kit (JDK) 8+

For IntelliJ IDEA run:
* IntelliJ IDEA 2018.3.3+

For building a jar:
* Maven 3+

## IntelliJ IDEA run
- git clone https://github.com/VirgilSecurity/sample-backend-java-nexmo
- Open IntelliJ IDEA -> File -> New -> Project from Existing Sources, locate `sample-backend-java-nexmo` and click `open`
- Select `Import project from external model` -> `Maven`, go `next` till `Please select project SDK` page
- Select in list of available JDKs `1.8.xxx` version or greater. If you haven't JDK of `1.8.xxx` version [install](https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html) it. `Finish` setup.
- Fill in your [credentials](#get-virgil-credentials) into the `sample-backend-java-nexmo/src/main/resources/`[`application.properties`](https://github.com/VirgilSecurity/sample-backend-java-nexmo/blob/master/src/main/resources/application.properties) file.
- Run application

If server started successfully you will see in the end of logs:
```
: Tomcat started on port(s): 3000 (http)
: Started ServerApplication
```

> If you get error `Error:java: javacTask: source release 8 requires target release 1.8` go to IntelliJ IDEA -> Preferences -> Build, Execution, Deployment -> Compiler -> Java Compiler and select `8` in `Project bytecode version` field.

## Get Virgil Credentials

If you don't have an account yet, [sign up for one](https://dashboard.virgilsecurity.com/signup) using your e-mail.

To generate a JWT the following values are required:

| Variable Name                     | Description                    |
|-----------------------------------|--------------------------------|
| virgil.app.id                     | ID of your Virgil Application. |
| virgil.api.private_key            | Private key of your API key that is used to sign the JWTs. |
| virgil.api.key_id                 | ID of your API key. A unique string value that identifies your account in the Virgil Cloud. |

## Building a Jar

Possibly, you want to build a Jar to deploy it on a remote server (e.g. [Now](https://zeit.co/now), [Heroku](https://www.heroku.com/)).

### Clone

Clone the repository from GitHub.

```
$ git clone https://github.com/VirgilSecurity/e3kit-kotlin.git
```

### Build sources

```
$ mvn clean package -DskipTests
```

JAR file will be build in `target` directory.

### Add Virgil Credentials to *application.properties*

- open `target` directory at the project folder
- create a `application.properties` file
- fill it with your account credentials (take a look at the [`application.properties`](https://github.com/VirgilSecurity/sample-backend-java-nexmo/blob/master/src/main/resources/application.properties) file to find out how to setup your own `application.properties` file)
- save the `application.properties` file

### Run the Server

```
$ java -jar server.jar
```

Now, use your client code to make a request to get a JWT from the sample backend that is working on http://localhost:3000.

You can verify the server with a command:

```bash
$ curl -X POST -H "Content-Type: application/json" \
  -d '{"identity":"my_identity"}' \
  http://localhost:3000/authenticate
```

The response should looks like:

```json
{"authToken":"my_identity-b5ba1680-4d5c-4b2e-9890-a0500d3c9bfe"}
```

## Specification

### /authenticate endpoint
This endpoint is an example of users authentication. It takes user `identity` and responds with unique token.

```http
POST https://localhost:3000/authenticate HTTP/1.1
Content-type: application/json;

{
    "identity": "string"
}

Response:

{
    "authToken": "string"
}
```

### /virgil-jwt endpoint
This endpoint checks whether a user is authorized by an authorization header. It takes user's `authToken`, finds related user identity and generates a `virgilToken` (which is [JSON Web Token](https://jwt.io/)) with this `identity` in a payload. Use this token to make authorized api calls to Virgil Cloud.

```http
GET https://localhost:3000/virgil-jwt HTTP/1.1
Content-type: application/json;
Authorization: Bearer <authToken>

Response:

{
    "virgilToken": "string"
}
```

### /nexmo-jwt endpoint
This endpoint checks whether a user is authorized by an authorization header. It takes user's `authToken`, finds related user identity and generates a `nexmoToken` (which is [JSON Web Token](https://jwt.io/)) with this `identity` in a payload. Use this token to make authorized api calls to Nexmo services. 
> Current implementation provides only `/v1/sessions/**` and `/v1/conversations/**` ACLs (It's enough for text chat). You can modify this server to suit your needs for example passing ACLs as a query parameters to GET request and then add requested ACLs to you JWT. 

```http
GET https://localhost:3000/virgil-jwt HTTP/1.1
Content-type: application/json;
Authorization: Bearer <authToken>

Response:

{
    "nexmoToken": "string"
}
```

## Virgil JWT Generation
To generate JWT, you need to use the `JwtGenerator` class from the SDK.

```Java
public JwtGenerator jwtGenerator() throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();
    PrivateKey privateKey = crypto.importPrivateKey(ConvertionUtils.base64ToBytes(this.apiKey));
    AccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();

    JwtGenerator jwtGenerator = new JwtGenerator(appId, privateKey, apiKeyIdentifier,
        TimeSpan.fromTime(1, TimeUnit.HOURS), accessTokenSigner);

    return jwtGenerator;
}

```
Then you need to provide an HTTP endpoint which will return the JWT with the user's identity as a JSON.

For more details take a look at the [AuthenticationService.java](src/main/java/com/virgilsecurity/demo/server/service/AuthenticationService.java) file.



## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
