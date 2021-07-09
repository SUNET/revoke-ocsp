FROM golang:1.16

WORKDIR /ocsp
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE 8002

CMD ["revoke-ocsp"]
