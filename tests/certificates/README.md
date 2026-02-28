## Create self signed root CA (DEV)

    openssl ecparam -name prime256v1 -genkey -noout -out [yourname].root-ca.dev.key


    openssl req -x509 -new -sha256 -days 3650 \
      -key [yourname].root-ca.dev.key \
      -out [yourname].root-ca.dev.crt \
      -subj "/C=Country Code/ST=Country/L=City/O=[yourname]/OU=Dev/CN=[yourname] Root CA (DEV)" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash"


## Create intermediate

    openssl ecparam -name prime256v1 -genkey -noout -out [yourname].intermediate-ca.dev.key


    openssl req -new -sha256 \
      -key [yourname].intermediate-ca.dev.key \
      -out [yourname].intermediate-ca.dev.csr \
      -subj "/C=Country Code/ST=Country/L=City/O=[yourname]/OU=Dev/CN=[yourname] Intermediate CA (DEV)"

create v3_intermediate.ext with:

    echo "basicConstraints=critical,CA:TRUE,pathlen:0
    keyUsage=critical,keyCertSign,cRLSign
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer" > v3_intermediate.ext


    openssl x509 -req -sha256 \
      -in [yourname].intermediate-ca.dev.csr \
      -CA [yourname].root-ca.dev.crt \
      -CAkey [yourname].root-ca.dev.key \
      -CAcreateserial \
      -out [yourname].intermediate-ca.dev.crt \
      -days 1825 \
      -extfile v3_intermediate.ext

## Create certificate

    openssl ecparam -name prime256v1 -genkey -noout -out [yourname].dev.key


    openssl req -new -sha256 \
      -key [yourname].dev.key \
      -out [yourname].dev.csr \
      -subj "/C=US/ST=State/L=City/O=[yourname]/OU=Dev/CN=dev.[yourname].local"


    echo "basicConstraints=critical,CA:FALSE
    keyUsage=critical,digitalSignature
    extendedKeyUsage=serverAuth
    subjectAltName=DNS:dev.[yourname].local,DNS:localhost" > v3.[yourname].dev.ext


    openssl x509 -req -sha256 \
      -in [yourname].dev.csr \
      -CA [yourname].intermediate-ca.dev.crt \
      -CAkey [yourname].intermediate-ca.dev.key \
      -CAcreateserial \
      -out [yourname].dev.crt \
      -days 825 \
      -extfile v3.[yourname].dev.ext


    cat [yourname].dev.crt [yourname].intermediate-ca.dev.crt > [yourname].fullchain.dev.crt
