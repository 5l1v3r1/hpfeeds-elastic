package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/d1str0/hpfeeds"
	"github.com/olivere/elastic"
)

func main() {
	var (
		host    string
		port    int
		ident   string
		auth    string
		channel string
	)
	flag.StringVar(&host, "host", "mhnbroker.threatstream.com", "target host")
	flag.IntVar(&port, "port", 10000, "hpfeeds port")
	flag.StringVar(&ident, "ident", "test-ident", "ident username")
	flag.StringVar(&auth, "secret", "test-secret", "ident secret")
	flag.StringVar(&channel, "channel", "test-channel", "channel to subscribe to")

	flag.Parse()

	hp := hpfeeds.NewClient(host, port, ident, auth)
	hp.Log = true
	messages := make(chan hpfeeds.Message)

	go processPayloads(messages)

	for {
		fmt.Println("Connecting to hpfeeds server.")
		hp.Connect()

		// Subscribe to "flotest" and print everything coming in on it
		hp.Subscribe(channel, messages)

		// Wait for disconnect
		<-hp.Disconnected
		fmt.Println("Disconnected, attempting to reconnect in 10 seconds...")
		time.Sleep(10 * time.Second)
	}
}

type Payload struct {
	App string
}

func processPayloads(messages chan hpfeeds.Message) {
	client, err := elastic.NewClient()
	if err != nil {
		log.Fatalf("Error creating new elastic client: %v", err)
	}

	n := 0

	bulkRequest := client.Bulk()

	var p Payload
	for mes := range messages {
		n++

		if err = json.Unmarshal(mes.Payload, &p); err != nil {
			log.Printf("Error unmarshaling json: %s\n", err.Error())
			continue
		}

		req := elastic.NewBulkIndexRequest().Index("mhn-" + p.App).Type("json").Doc(string(mes.Payload))
		bulkRequest = bulkRequest.Add(req)

		if n%100 == 0 {
			ctx := context.Background()
			fmt.Println("Processing batch...")
			res, err := bulkRequest.Do(ctx)
			if err != nil {
				log.Println(err)
			} else if res.Errors {
				log.Printf("%#v\n", res.Failed()[0].Error)
			} else {
				log.Printf("Done with %d records\n", n)
			}

		}
	}
}
