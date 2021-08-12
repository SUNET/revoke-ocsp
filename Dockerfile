FROM golang:1.16

WORKDIR /usr/src/app

COPY go.* ./
RUN go mod download

COPY . ./
RUN go install -v ./...

EXPOSE 8002

CMD ["revoke-ocsp"]
