# Messages pour MilleGrilles

## Parametres

CAFILE=/var/opt/millegrilles/configuration/pki.millegrille.cert
CERTFILE=/var/opt/millegrilles/secrets/pki.messages_backend.cert
KEYFILE=/var/opt/millegrilles/secrets/pki.messages_backend.cle
MG_MONGO_HOST=localhost
MG_MQ_HOST=localhost
MG_REDIS_PASSWORD_FILE=/var/opt/millegrilles/secrets/passwd.redis.txt
MG_REDIS_URL=rediss://client_rust@localhost:6379#insecure
RUST_LOG=warn,millegrilles_messages_rust=info,millegrilles_messages_rust::commandes=debug
TOKIO_WORKER_THREADS=2
