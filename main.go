package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/d1str0/hpfeeds"
	"github.com/olivere/elastic/v7"
)

const Version = "v0.0.2"
const MHNIndexName = "mhn-community-data-"

var Apps = []string{
	"agave",
	"dionaea",
	"p0f",
	"amun",
	"kippo",
	"cowrie",
	"snort",
	"conpot",
	"suricata",
	"elastichoney",
}

var (
	host         string
	port         int
	ident        string
	auth         string
	channel      string
	elasticURL   string
	initMapping  bool
	initOverride bool
	mappingFile  string
)

func main() {
	fmt.Printf("///- Running hpfeeds-elastic ingester\n")
	fmt.Printf("///- Version: %s\n", Version)

	flag.StringVar(&host, "host", "mhnbroker.threatstream.com", "target host")
	flag.IntVar(&port, "port", 10000, "hpfeeds port")
	flag.StringVar(&ident, "ident", "test-ident", "ident username")
	flag.StringVar(&auth, "secret", "test-secret", "ident secret")
	flag.StringVar(&channel, "channel", "test-channel", "channel to subscribe to")
	flag.StringVar(&elasticURL, "elastic-url", "http://127.0.0.1:9200", "Elastic Search to connect to")
	flag.BoolVar(&initMapping, "init", false, "Initialize index")
	flag.BoolVar(&initOverride, "init-override", false, "Delete a previously matching index and override")
	flag.StringVar(&mappingFile, "mapping-file", "map.json", "JSON file for index mapping")

	flag.Parse()

	hp := hpfeeds.NewClient(host, port, ident, auth)
	hp.Log = true
	messages := make(chan hpfeeds.Message)

	client, err := elastic.NewClient(elastic.SetURL(elasticURL))
	if err != nil {
		log.Fatalf("Error creating new elastic client: %v", err)
	}

	// Check if we need to init the index with a mapping file
	if initMapping {
		if initOverride {
			deleteIndex(client)
		}
		createIndex(client, mappingFile)
	}

	go processPayloads(messages, client)

	for {
		fmt.Println("Connecting to hpfeeds server.")
		hp.Connect()
		fmt.Println("Connected.")

		// Subscribe to "flotest" and print everything coming in on it
		hp.Subscribe(channel, messages)

		// Wait for disconnect
		<-hp.Disconnected
		fmt.Println("Disconnected, attempting to reconnect in 10 seconds...")
		time.Sleep(10 * time.Second)
	}
}

func deleteIndex(client *elastic.Client) {
	ctx := context.Background()
	for _, app := range Apps {
		index := fmt.Sprintf("%s%s", MHNIndexName, app)
		deleteIndex, err := client.DeleteIndex(index).Do(ctx)
		if err != nil {
			log.Fatal(err.Error())
		}
		if !deleteIndex.Acknowledged {
			// Not acknowledged
			log.Fatal("Delete index: Not acknowledged")
		}
	}
}

func createIndex(client *elastic.Client, mappingFile string) {
	buf, err := ioutil.ReadFile(mappingFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !json.Valid(buf) {
		log.Fatal("JSON in mapping file invalid")
	}

	ctx := context.Background()

	for _, app := range Apps {
		index := fmt.Sprintf("%s%s", MHNIndexName, app)
		createIndex, err := client.CreateIndex(index).Body(string(buf)).Do(ctx)
		if err != nil {
			// Handle error
			log.Fatal(err.Error())
		}
		if !createIndex.Acknowledged {
			// Not acknowledged
			log.Fatal("Create index: Not acknowledged")
		}
	}
}

type Payload struct {
	App string `json:"app"`

	DestLatitude  float64 `json:"dest_latitude"`
	DestLongitude float64 `json:"dest_longitude"`
	SrcLatitude   float64 `json:"src_latitude"`
	SrcLongitude  float64 `json:"src_longitude"`
}

func processPayloads(messages chan hpfeeds.Message, client *elastic.Client) {
	n := 0

	bulkRequest := client.Bulk()

	var p Payload
	for mes := range messages {
		n++

		if err := json.Unmarshal(mes.Payload, &p); err != nil {
			log.Printf("Error unmarshaling json: %s\n", err.Error())
			log.Printf(string(mes.Payload))
			continue
		}

		DestLocation := fmt.Sprintf("%f,%f", p.DestLatitude, p.DestLongitude)
		SrcLocation := fmt.Sprintf("%f,%f", p.SrcLatitude, p.SrcLongitude)
		Timestamp := time.Now().Format(time.RFC3339)

		var f interface{}
		json.Unmarshal(mes.Payload, &f)

		m := f.(map[string]interface{})
		m["src_location"] = SrcLocation
		m["dest_location"] = DestLocation
		m["timestamp"] = Timestamp

		index := fmt.Sprintf("%s%s", MHNIndexName, p.App)
		req := elastic.NewBulkIndexRequest().Index(index).Type("_doc").Doc(m)
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
