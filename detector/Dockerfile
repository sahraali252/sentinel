FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY config ./config
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sentinel-detector ./cmd/detector

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sentinel-detector /sentinel-detector
COPY --from=build /src/config /config
EXPOSE 8080
ENTRYPOINT ["/sentinel-detector"]
