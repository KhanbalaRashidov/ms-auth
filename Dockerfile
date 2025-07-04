FROM golang:1.24-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download
RUN go mod verify

# Copy source code
COPY . .

# Generate swagger docs
RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN swag init -g ./cmd/main.go --output ./docs

COPY . .



RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ms-auth ./cmd/main.go

FROM alpine:latest

WORKDIR /app

ARG DB_HOST
ARG DB_NAME
ARG DB_USERNAME
ARG DB_PASSWORD
ARG REDIS_HOST
ARG REDIS_PASSWORD
ARG JWT_SECRET_KEY
ARG SMTP_HOST
ARG SMTP_PORT
ARG SMTP_USERNAME
ARG SMTP_PASSWORD
ARG FROM_EMAIL
ARG FROM_NAME
ARG SMS_PROVIDER
ARG SMS_API_KEY
ARG SMS_API_SECRET
ARG RABBITMQ_USER
ARG RABBITMQ_PASSWORD
ARG RABBITMQ_HOST

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080
ENV ENVIRONMENT=production
ENV READ_TIMEOUT=30s
ENV WRITE_TIMEOUT=30s
ENV IDLE_TIMEOUT=120s

ENV DB_HOST=$DB_HOST
ENV DB_PORT=5432
ENV DB_USER=$DB_USERNAME
ENV DB_PASSWORD=$DB_PASSWORD
ENV DB_NAME=$DB_NAME
ENV DB_SSL_MODE=disable
ENV DB_MAX_OPEN_CONNS=100
ENV DB_MAX_IDLE_CONNS=10
ENV DB_CONN_MAX_LIFETIME=1h
ENV DB_CONN_MAX_IDLE_TIME=10m

ENV JWT_SECRET_KEY=$JWT_SECRET_KEY
ENV JWT_ISSUER=ms-auth
ENV JWT_AUDIENCE=ms-auth-api
ENV JWT_ACCESS_DURATION=1h
ENV JWT_REFRESH_DURATION=168h
ENV JWT_RESET_DURATION=1h
ENV JWT_VERIFICATION_DURATION=24h

ENV PASSWORD_MIN_LENGTH=8
ENV PASSWORD_MAX_LENGTH=128
ENV PASSWORD_REQUIRE_UPPER=true
ENV PASSWORD_REQUIRE_LOWER=true
ENV PASSWORD_REQUIRE_DIGIT=true
ENV PASSWORD_REQUIRE_SPECIAL=true
ENV PASSWORD_PREVENT_REUSE=5
ENV PASSWORD_MAX_AGE=90

ENV REDIS_HOST=$REDIS_HOST
ENV REDIS_PORT=6379
ENV REDIS_PASSWORD=$REDIS_PASSWORD
ENV REDIS_DB=0

ENV SMTP_HOST=$SMTP_HOST
ENV SMTP_PORT=$SMTP_PORT
ENV SMTP_USERNAME=$SMTP_USERNAME
ENV SMTP_PASSWORD=$SMTP_PASSWORD
ENV FROM_EMAIL=$FROM_EMAIL
ENV FROM_NAME=$FROM_NAME

ENV SMS_PROVIDER=$SMS_PROVIDER
ENV SMS_API_KEY=$SMS_API_KEY
ENV SMS_API_SECRET=$SMS_API_SECRET

#ENV RABBITMQ_USER=$RABBITMQ_USER
#ENV RABBITMQ_PASSWORD=$RABBITMQ_PASSWORD
#ENV RABBITMQ_HOST=$RABBITMQ_HOST
#ENV RABBITMQ_URL=amqp://$RABBITMQ_USER:$RABBITMQ_PASSWORD@$RABBITMQ_HOST:5672/ # DSN kimi

ENV RATE_LIMIT_LOGIN_ATTEMPTS=5
ENV RATE_LIMIT_LOGIN_WINDOW=15m
ENV RATE_LIMIT_REGISTER_ATTEMPTS=3
ENV RATE_LIMIT_REGISTER_WINDOW=1h
ENV RATE_LIMIT_REQUESTS_PER_MINUTE=100

ENV BLACKLIST_CHECK_ON_REGISTER=true
ENV BLACKLIST_CHECK_ON_LOGIN=true
ENV BLACKLIST_AUTO_CLEANUP=true
ENV BLACKLIST_CLEANUP_INTERVAL=24h

ENV SECURITY_ENABLE_MFA=true
ENV SECURITY_REQUIRE_EMAIL_VERIFY=false
ENV SECURITY_REQUIRE_PHONE_VERIFY=false
ENV SECURITY_SESSION_TIMEOUT=24h
ENV SECURITY_MAX_SESSIONS=5
ENV SECURITY_ALLOW_MULTIPLE_LOGINS=true
ENV SECURITY_IP_WHITELIST=""
ENV SECURITY_TRUSTED_PROXIES=""

ENV CORS_ALLOW_ORIGINS="*"
ENV CORS_ALLOW_METHODS=GET,POST,PUT,DELETE,OPTIONS
ENV CORS_ALLOW_HEADERS=Origin,Content-Type,Accept,Authorization
ENV CORS_ALLOW_CREDENTIALS=true
ENV CORS_EXPOSE_HEADERS=""
ENV CORS_MAX_AGE=12h


COPY --from=builder /app/ms-auth ./


RUN apk add --no-cache ca-certificates curl

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/actuator/health || exit 1
EXPOSE 8080

CMD ["./ms-auth"]