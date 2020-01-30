FROM golang:1.13-alpine3.10

RUN apk add --no-cache \
    git gcc musl-dev

RUN mkdir /src/
ADD ./ /src/

RUN cd /src/cmd/auth-service && \
    go build -ldflags '-extldflags "-fno-PIC -static"' -buildmode pie


FROM scratch

COPY --from=0 /src/cmd/auth-service/auth-service /auth-service

ENTRYPOINT ["/auth-service"]

CMD ["-addr=:8080", "-key=/data/auth-service.pem", "-dbPath=/data/auth-service.db"]
