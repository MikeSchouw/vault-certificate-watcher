FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /watcher .
FROM scratch
COPY --from=build /watcher /watcher
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/watcher"]
