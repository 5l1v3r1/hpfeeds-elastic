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
const BulkSize = 100

// Apps includes all currently supported honeypots we can expect from the
// community data. This list will be used to propogate all the ElasticSearch
// indexes we want to use, my appending the app name to MHNIndexName.
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
	"kippo",
	"wordpot",
}

// These will be used for command line variables.
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

	flag.StringVar(&host, "host", "mhnbroker.threatstream.com", "hpfeeds broker host")
	flag.IntVar(&port, "port", 10000, "hpfeeds port")
	flag.StringVar(&ident, "ident", "test-ident", "hpfeeds identity username")
	flag.StringVar(&auth, "secret", "test-secret", "hpfeeds identity secret")
	flag.StringVar(&channel, "channel", "test-channel", "hpfeeds channel to subscribe to")
	flag.StringVar(&elasticURL, "elastic-url", "http://127.0.0.1:9200", "ElasticSearch URL to connect to")
	flag.BoolVar(&initMapping, "init", false, "Initialize ES index")
	flag.BoolVar(&initOverride, "init-override", false, "Delete a previously matching ES index and override (WARNING: deletes all data in deleted indexes)")
	flag.StringVar(&mappingFile, "mapping-file", "map.json", "JSON file for index mapping (unlikely to need different from default)")

	flag.Parse()

	hp := hpfeeds.NewClient(host, port, ident, auth)
	hp.Log = true // Starts logging hpfeeds debug to STDOUT
	messages := make(chan hpfeeds.Message)

	client, err := elastic.NewClient(elastic.SetURL(elasticURL))
	if err != nil {
		log.Fatalf("Error creating new elastic client: %v", err)
	}

	// Check if we need to init the index with a mapping file
	if initMapping {
		// Check if we want to delete all indexes and restart with new mappings
		if initOverride {
			deleteIndex(client)
		}
		createIndex(client, mappingFile)
	}

	// Starts listening for messages and bulk processing them to ES.
	go processPayloads(messages, client)

	// Sets up a for loop for hpfeeds reconnection in case of disconnect
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

// deleteIndex will delete all indexes of the name
// MHNIndexName + App for each App in Apps list.
func deleteIndex(client *elastic.Client) {
	ctx := context.Background() // Default setting, required.
	for _, app := range Apps {
		index := fmt.Sprintf("%s%s", MHNIndexName, app)
		deleteIndex, err := client.DeleteIndex(index).Do(ctx)
		if err != nil {
			// Print error but don't exit. Some indexes may already be deleted
			// so we continue even in case of error.
			log.Print(err.Error())
		}
		if !deleteIndex.Acknowledged {
			// Not acknowledged
			log.Print("Delete index: Not acknowledged")
		}
	}
}

// createIndex will create all indexes of the name
// MHNIndexName + App for each App in Apps list and will also set mapping of
// index to provided json file.
func createIndex(client *elastic.Client, mappingFile string) {
	// Read mapping json file.
	buf, err := ioutil.ReadFile(mappingFile)
	if err != nil {
		log.Print(err.Error())
	}

	// Sanity check
	if !json.Valid(buf) {
		log.Print("JSON in mapping file invalid")
	}

	ctx := context.Background() // Default setting, required
	for _, app := range Apps {
		index := fmt.Sprintf("%s%s", MHNIndexName, app)
		createIndex, err := client.CreateIndex(index).Body(string(buf)).Do(ctx)
		if err != nil {
			// Print error but don't exit. Some indexes may already be created
			// so we continue even in case of error.
			log.Print(err.Error())
		}
		if !createIndex.Acknowledged {
			// Not acknowledged
			log.Print("Create index: Not acknowledged")
		}
	}
}

// Payload holds a small portion of data expected in each hpfeeds message. This
// data is minimum required and needed for use in creating new fields.
type Payload struct {
	App string `json:"app"` // Honeypot software type

	DestLatitude  float64 `json:"dest_latitude"`
	DestLongitude float64 `json:"dest_longitude"`
	SrcLatitude   float64 `json:"src_latitude"`
	SrcLongitude  float64 `json:"src_longitude"`
}

func processPayloads(messages chan hpfeeds.Message, client *elastic.Client) {
	var p Payload // Temp object for continuous reuse

	bulkRequest := client.Bulk() // Prepare a bulk request to ES.

	n := 0
	for mes := range messages {
		n++

		// Try and parse hpfeeds message from JSON into Payload struct
		if err := json.Unmarshal(mes.Payload, &p); err != nil {
			log.Printf("Error unmarshaling json: %s\n", err.Error())
			log.Printf(string(mes.Payload))

			// Simply skip this message if we can't parse it
			continue
		}

		// Take Lat and Lon for Src and Dest IPs, concatenate this to create a
		// single value that fits ES "geopoint" value type.
		DestLocation := fmt.Sprintf("%f,%f", p.DestLatitude, p.DestLongitude)
		SrcLocation := fmt.Sprintf("%f,%f", p.SrcLatitude, p.SrcLongitude)

		// Get current time for ES timeseries
		Timestamp := time.Now().Format(time.RFC3339)

		// Create interface to hold *whatever* data actually is in the hpfeeds message
		var f interface{}

		// Ignore error as we've done this before.
		json.Unmarshal(mes.Payload, &f)

		// Cast to map so we can add in a few fields
		m := f.(map[string]interface{})
		m["src_location"] = SrcLocation
		m["dest_location"] = DestLocation
		m["timestamp"] = Timestamp

		// Add object to bulk request under proper index name.
		index := fmt.Sprintf("%s%s", MHNIndexName, p.App)
		req := elastic.NewBulkIndexRequest().Index(index).Type("_doc").Doc(m)
		bulkRequest = bulkRequest.Add(req)

		// Process batch when we hit BulkSize.
		if n%BulkSize == 0 {
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

			n = 0
		}
	}
}
