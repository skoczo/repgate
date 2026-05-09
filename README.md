# !!!WORK IN PROGRESS, NOT READY YET!!!
![Coverage](https://img.shields.io/badge/Coverage-11-red)

# Repgate

Repgate(reputation gate) is a small Go service for storing and serving IP reputation data over HTTP. It uses Chi for routing and SQLite for lightweight local persistence, which makes it simple to run in development and easy to package in a container.

Especially to be run with cloudflared where client source ip is in the header.

## Features
HTTP service written in Go

Routing built with Chi, a lightweight and composable router for Go HTTP services

SQLite-backed persistence for local development and simple deployments

SQL-based database initialization and migrations

Dev Container setup for a reproducible VS Code development environment


## Requirements
Go 1.25 or newer if using the latest modernc.org/sqlite, because recent releases of that driver require Go 1.25+.

GNU Make

VS Code with the Go extension if you want to use the provided Dev Container setup

Getting Started
1. Clone the repository
```
git clone https://github.com/skoczo/repgate.git
cd repgate
```

2. Install dependencies
If you are using a Go toolchain compatible with the latest SQLite driver:

```
go get modernc.org/sqlite
go mod tidy
```
If your environment is still on an older Go version, pin a compatible driver version instead:


```
go get modernc.org/sqlite@v1.39.1
go mod tidy
```

3. Build the binary

```
make build
The build command produces the application binary in bin/repgate.
```

4. Run the service
```
./bin/repgate
```
## Database and Migrations
The service uses SQLite through database/sql and the modernc.org/sqlite driver, which is a CGO-free SQLite driver for Go.

The current codebase expects:

- a writable database path under data/

- SQL migration files under db/migrations/

When running the app from VS Code, make sure the process starts with the repository root as the working directory. Relative paths such as data/repgate.db and db/migrations/001_init.sql are resolved from the current working directory, not from the location of the .go file.

You should also create internal-config.yaml in main directory. It should be copty of config.yaml but with your configuration. internal-* files are not stored in the repo


## Dev Container
The repository includes a Dev Container configuration for VS Code. 