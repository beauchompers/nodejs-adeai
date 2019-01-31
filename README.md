# Active Directory External Authentication Interface Example

This is a External Authentication Interface (EAI) application using NodeJS, it authenticates against Active Directory and returns a full user cred to WebSEAL.

Based this EAI on the pattern described by Philip Nye here: [ISAM for Web without a user registry](https://philipnye.com/2015/02/25/isam-for-web-without-a-user-registry-new-and-improved/)

## Setup Instructions

Make sure you have NodeJS installed, and run npm install to bring down the required packages.

Edit the adeai.properties file to include information about the Active Directory Server you're going to use, and the certificate and key the app will present, this is an authentication app after all.

```text
# Example properties file for adeai app
[main]
ad_url = ldaps://activedirectory.com
ad_basedn = dc=activedirectory,dc=com0
ad_domain = @activedirectory.com
ad_user = svc_adeai@activedirectory.com
ad_pass = thisisthemostsecurepasswordintheworldtrustme
key = adeai.key
certificate = adeai.cer
```

### Configure WebSEAL

You'll need to enable EAI Auth, and set the various triggers as appropriate, see Philip's articale for more info.

## Running the App

You can use nodemon, or use the command:

```bash
node ./bin/www
```

Application also runs as a Docker Container, Dockerfile is included in the repo to build the container, and you can build/run like this:

```bash
docker build -t adeai .
docker run -it --name adeai adeai -p 3000:3000
```