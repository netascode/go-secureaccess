[![Tests](https://github.com/netascode/go-secureclient/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/go-secureclient/actions/workflows/test.yml)

# go-secureclient

`go-secureclient` is a Go client library for Cisco Secure Access

## Getting Started

### Installing

To start using `go-secureaccess`, install Go and `go get`:

`$ go get -u github.com/netascode/go-secureaccess`

### Basic Usage

#### Retrieving information

```go
package main

import "github.com/netascode/go-secureaccess"

func main() {
    client, _ := fmc.NewClient("https://api.sse.cisco.com", "apiKey", "apiKeySecret")
	res, err := client.Get(ctx, "/policies/v2/objects/networkObjects")
    println(res.Get("results.0.name").String())
}
```

## Documentation

See the [documentation](https://godoc.org/github.com/netascode/go-secureaccess) for more details.
