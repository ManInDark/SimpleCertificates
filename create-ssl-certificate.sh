openssl genrsa -out private.key 4096
openssl req -new -key private.key -out public.csr -subj '/CN=example.com/L=EX/C=EX'
cat - > example.ext
    authorityKeyIdentifier=keyid,issuer
    basicConstraints=CA:FALSE
    keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign
    subjectAltName = @alt_names

    [alt_names]
    DNS.1 = example.com
name=`curl -X POST --data-binary @public.csr $1/csr`
curl -X POST --data-binary @example.ext "$1/ext/$name"
curl "$1/sslsign?name=$name"
curl "$1/sslretrieve?name=$name" > public.crt