FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /vakt ./cmd/vakt

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /vakt /vakt
VOLUME /data
EXPOSE 80 443
ENTRYPOINT ["/vakt"]
