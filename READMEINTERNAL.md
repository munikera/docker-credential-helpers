# Private Registry Authentication POC Instructions

- [Overview](#overview)
- [Docker Credential Helper + Authentication Proxy](#docker-credential-helper--authentication-proxy)
- [X-API-Key + Authentication Proxy](#x-api-key--authentication-proxy)

## Overview

This POC shows how a Minerva user will be able to authenticate to their private Docker registry using a (client_id&client_secret) or api-key.


*** Make sure that you have [Golang](#https://go.dev/dl/) installed in your system.
## Docker Credential Helper + Authentication Proxy
1. Use `make` to build osxkeychain credential helper. That will leave an executable in the `bin` directory inside the repository.

```sh
make osxkeychain
```

2. Put the binary in your `$PATH`, so Docker can find it.

```sh
sudo cp bin/build/docker-credential-osxkeychain /usr/local/bin/docker-credential-intelosxkeychain
```

3. Disconnect from VPN and unset proxy. This is required for the local nginx instance to succesfully send a request to the minerva auth-api.
```sh
unset https_proxy
unset http_proxy 
unset HTTPS_PROXY
unset HTTP_PROXY 
unset ALL_PROXY 
unset all_proxy
```

4. Start docker registry and authentication proxy
```sh
docker compose up
```

5. Edit ~/.docker/config.json to use intelosxkeychain credential helper.
```json
{
  "credsStore": "intelosxkeychain"
}
```

6. Tag hello-world image as myfirstimage
```sh
docker image tag hello-world localhost:5043/myfirstimage
```

7. Push myfirstimage to the private registry localhost:5043
```sh
docker push localhost:5043/myfirstimage
```


## X-API-Key + Authentication Proxy
1. Comment out line 47-50 in ./registry/auth/nginx.conf so that Basic authentication is not enforced.

2. Edit ~/.docker/config.json to add a custom http-header. Replace <YOUR_ACCESS_TOKEN> with a valid minerva ACCESS_TOKEN.

```json
{
        "HttpHeaders": {
                "x-meta-authorization": "Bearer <YOUR_ACCESS_TOKEN>"
        }
}
```


3. Disconnect from VPN and unset proxy. This is required for the local nginx instance to succesfully send a request to the minerva auth-api.
```sh
unset https_proxy
unset http_proxy 
unset HTTPS_PROXY
unset HTTP_PROXY 
unset ALL_PROXY 
unset all_proxy
```

4. Start docker registry and authentication proxy

```sh
docker compose up
```
5. Tag hello-world image as myfirstimage
```sh
docker image tag hello-world localhost:5043/myfirstimage
```

6. Push myfirstimage to the private registry localhost:5043
```sh
docker push localhost:5043/myfirstimage
```


**** For Window Setup *****
1. Open cmd.exe with Administrator privilege.

1. Use `make` to build wincred credential helper. That will leave an executable in the `bin` directory inside the repository.

```sh
make wincred
```

2. Put the binary in your `$PATH`, so Docker can find it.

```sh
for /f "delims=" %i in ('where docker-credential-wincred') do set docker_path=%i
copy bin\build\docker-credential-wincred.exe "%docker_path%"
Overwirte : Yes
```

3. Disconnect from VPN and unset proxy. This is required for the local nginx instance to succesfully send a request to the minerva auth-api.
```sh
set https_proxy=
set http_proxy=
set HTTPS_PROXY=
set HTTP_PROXY=
set ALL_PROXY=
set all_proxy=
set CLIENT_ID=<your_client_id>
set CLIENT_SECRET=<your_client_secret>
```

4. Start docker registry and authentication proxy
```sh
docker compose up
```

5. Open new cmd.exe terminal, repeat step 3

6. Tag hello-world image as myfirstimage
```sh
docker image tag hello-world localhost:5043/myfirstimage
```

7. Push myfirstimage to the private registry localhost:5043
```sh
docker push localhost:5043/myfirstimage
```
