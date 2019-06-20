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

	DestAreaCode     int     `json:"dest_area_code"`
	DestCity         string  `json:"dest_city"`
	DestCountryCode  string  `json:"dest_country_code"`
	DestCountryCode3 string  `json:"dest_country_code3"`
	DestCountryName  string  `json:"dest_country_name"`
	DestDMACode      int     `json:"dest_dma_code"`
	DestLatitude     float64 `json:"dest_latitude"`
	DestLocation     string  `json:"dest_location"`
	DestLongitude    float64 `json:"dest_longitude"`
	DestMetroCode    int     `json:"dest_metro_code"`
	DestOrg          string  `json:"dest_org"`
	DestPort         int     `json:"dest_port"`
	DestPostalCode   string  `json:"dest_postal_code"`
	DestRegion       string  `json:"dest_region"`
	DestRegionName   string  `json:"dest_region_name"`
	DestTimeZone     string  `json:"dest_time_zone"`

	// Dionaea specific
	DionaeaAction string `json:"dionaea_action,omitempty"`

	Direction string `json:"direction"`

	// Elastichoney specific
	ElastichoneyForm    string `json:"elastichoney_form,omitempty"`
	ElastichoneyPayload string `json:"elastichoney_payload,omitempty"`

	// Snort/Suricata specific
	EthDst string `json:"eth_dst,omitempty"`
	EthSrc string `json:"eth_src,omitempty"`

	IDSType string `json:"ids_type"`

	// Snort/Suricata specific
	IPID  int `json:"ip_id,omitempty"`
	IPLEN int `json:"ip_len,omitempty"`
	IPTOS int `json:"ip_tos,omitempty"`
	IPTTL int `json:"ip_ttl,omitempty"`

	MHNIP   string `json:"mhn_ip"`
	MHNUUID string `json:"mhn_uuid"`

	// p0f specific
	P0fApp    string `json:"p0f_app,omitempty"`
	P0fLink   string `json:"p0f_link,omitempty"`
	P0fOS     string `json:"p0f_os,omitempty"`
	P0fUptime string `json:"p0f_uptime,omitempty"`

	Protocol string `json:"protocol"`

	// Elastichoney specific
	RequestURL string `json:"request_url,omitempty"`

	Sensor    string `json:"sensor"`
	Severity  string `json:"severity"`
	Signature string `json:"signature"`

	// Snort specific
	SnortClassification int    `json:"snort_classification,omitempty"`
	SnortHeader         string `json:"snort_header,omitempty"`
	SnortPriority       int    `json:"snort_priority,omitempty"`

	SrcAreaCode     int     `json:"src_area_code"`
	SrcCity         string  `json:"src_city"`
	SrcCountryCode  string  `json:"src_country_code"`
	SrcCountryCode3 string  `json:"src_country_code3"`
	SrcCountryName  string  `json:"src_country_name"`
	SrcDMACode      int     `json:"src_dma_code"`
	SrcIP           string  `json:"src_ip"`
	SrcLatitude     float64 `json:"src_latitude"`
	SrcLocation     string  `json:"src_location"`
	SrcLongitude    float64 `json:"src_longitude"`
	SrcMetroCode    int     `json:"src_metro_code"`
	SrcOrg          string  `json:"src_org"`
	SrcPort         int     `json:"src_port"`
	SrcPostalCode   string  `json:"src_postal_code"`
	SrcRegion       string  `json:"src_region"`
	SrcRegionName   string  `json:"src_region_name"`
	SrcTimeZone     string  `json:"src_time_zone"`

	// Suricata specific
	SuricataAction       string `json:"suricata_action,omitempty"`
	SuricataSignatureID  int    `json:"suricata_signature_id,omitempty"`
	SuricataSignatureRev int    `json:"suricata_signature_rev,omitempty"`

	// Kippo/Cowrie specific
	SSHPassword string `json:"ssh_password,omitempty"`
	SSHUsername string `json:"ssh_username,omitempty"`
	SSHVersion  string `json:"ssh_version,omitempty"`

	// Snort/Suricata specific
	TCPFlags string `json:"tcp_flags,omitempty"`
	TCPLen   int    `json:"tcp_len,omitempty"`

	Timestamp string `json:"timestamp"`

	Transport string `json:"transport"`
	Type      string `json:"type"`

	// Snort/Suricata specific
	UDPLen int `json:"udp_len,omitempty"`

	// Elastichoney specific
	UserAgent string `json:"user_agent,omitempty"`

	VendorProduct string `json:"vendor_product"`
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

		p.DestLocation = fmt.Sprintf("%f,%f", p.DestLatitude, p.DestLongitude)
		p.SrcLocation = fmt.Sprintf("%f,%f", p.SrcLatitude, p.SrcLongitude)
		p.Timestamp = time.Now().Format(time.RFC3339)

		index := fmt.Sprintf("%s%s", MHNIndexName, p.App)
		req := elastic.NewBulkIndexRequest().Index(index).Type("_doc").Doc(p)
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
