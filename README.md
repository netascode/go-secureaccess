[![Tests](https://github.com/netascode/go-secureaccess/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/go-secureaccess/actions/workflows/test.yml)

# go-secureaccess

`go-secureaccess` is a Go client library for Cisco Secure Access

## Getting Started

### Installing

To start using `go-secureaccess`, install Go and `go get`:

`$ go get -u github.com/netascode/go-secureaccess`

### Basic Usage

#### Retrieving information

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/netascode/go-secureaccess"
)

func main() {
	client, err := secureaccess.NewClient("https://api.sse.cisco.com", "apiKey", "apiKeySecret")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	res, err := client.Get(ctx, "/policies/v2/objects/networkObjects")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Get("results.0.name").String())
}
```

## Documentation

See the [documentation](https://godoc.org/github.com/netascode/go-secureaccess) for more details.
