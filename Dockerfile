# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

# Build Geth in a stock Go builder container
FROM golang:1.20-alpine as builder

RUN apk add --no-cache build-base libc-dev
RUN apk add --no-cache gcc musl-dev linux-headers git valgrind

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod /go-ethereum/
COPY go.sum /go-ethereum/
RUN cd /go-ethereum && go mod download

ADD . /go-ethereum
ENV CGO_CFLAGS="-O -D__BLST_PORTABLE__"
ENV CGO_CFLAGS_ALLOW="-O -D__BLST_PORTABLE__"
RUN cd /go-ethereum && go run build/ci.go install -static ./cmd/geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates valgrind
COPY --from=builder /go-ethereum/build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp
# Create a directory for the valgrind logs
RUN mkdir /var/log/geth
# Ensure the directory is writable by any user
RUN chmod 777 /var/log/geth
# Wrap the geth command with valgrind, assuming you want to do this by default
ENTRYPOINT ["sh", "-c", "valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes /usr/local/bin/geth 2>&1 | tee /var/log/geth/valgrind.log"]

# Add some metadata labels to help programatic image consumption
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM"
