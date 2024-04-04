package DbCall

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"example.com/m/Utils"
	"github.com/elastic/go-elasticsearch/esapi"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/joho/godotenv"
)

var Es *elasticsearch.Client
var err error

func ConnectToEs() {

	err = godotenv.Load(Utils.DirEnv("rest.env"))
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ELASTIC_PASSWORD := os.Getenv("ELASTIC_PASSWORD")
	cfg := elasticsearch.Config{
		Addresses: []string{
			"http://localhost:9200",
			// "http://es01:9200",
		},
		Username: "elastic",
		Password: ELASTIC_PASSWORD,
	}

	Es, err = elasticsearch.NewClient(cfg)
	if err != nil {
		fmt.Println("[ES_CONNECTION] Connection error :=> ", err)
	}
	fmt.Println(Es.Info())
	fmt.Println("ES Connection successful")

}

func IncreaseLimit() {

	templateSettings := `{
		"index_patterns": ["*"],
		"settings": {
			"index.mapping.total_fields.limit": 4000
		}
	}`

	req := esapi.IndicesPutTemplateRequest{
		Name: "increase_es_limit",
		Body: strings.NewReader(templateSettings),
	}

	res, err := req.Do(context.Background(), Es)
	if err != nil {
		fmt.Println("[ES_CreateTemplate] Error creating index template:", err)

	}
	defer res.Body.Close()

	resp, _ := ioutil.ReadAll(res.Body)

	if res.IsError() {
		fmt.Println("[ES_CreateTemplate]", res.StatusCode, string(resp))

	} else {
		fmt.Println("[ES_CreateTemplate] Index template created/updated successfully!")
	}

}

func UploadDataEs(filename string, tool string, data map[string]interface{}) {
	fmt.Println("[ES UPLOAD" + tool + "]" + " Uploading data to es")
	IncreaseLimit()
	jsonString, _ := json.Marshal(data)
	req := esapi.IndexRequest{
		Index:      filename,
		DocumentID: tool,
		Body:       strings.NewReader(string(jsonString)),
	}
	res, err := req.Do(context.Background(), Es)
	if err != nil {
		fmt.Println("[ES UPLOAD "+tool+" ]", err.Error())
	}
	defer res.Body.Close()

	if res.IsError() {
		fmt.Println("[ES UPLOAD "+tool+" ]"+" upload request failed:", res.Status(), data)
	}

	fmt.Println("[ES UPLOAD "+tool+" ]", res.String())
	fmt.Println("[ES UPLOAD " + tool + "]" + " Uploaded data to ES! ")
}

func SearchEs(filehash string, tool string) map[string]interface{} {

	index := filehash
	docID := tool

	req := esapi.GetRequest{
		Index:      index,
		DocumentID: docID,
	}

	res, err := req.Do(context.Background(), Es)
	if err != nil {
		fmt.Println("[ES SEARCH] Error retrieving document:", err)
	}

	// fmt.Println("[ES SEARCH "+tool+"]", res.String())
	defer res.Body.Close()
	if res.IsError() {
		fmt.Println("[ES SEARCH "+tool+"]"+" Error response:", res.Status(), res.String())

	} else {
		jsonString := res.String()[len("[200 OK] "):]

		var resp map[string]interface{}
		err = json.Unmarshal([]byte(jsonString), &resp)
		if err != nil {
			fmt.Println("[ES SEARCH] Error:", err)
		}
		return resp
	}

	return nil
}

func AllIndices() []map[string]interface{} {
	res, err := esapi.CatIndicesRequest{Format: "json"}.Do(context.Background(), Es)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	jsonString := res.String()[len("[200 OK] "):]

	var resp []map[string]interface{}
	err = json.Unmarshal([]byte(jsonString), &resp)
	if err != nil {
		fmt.Println("[ALL INDICES] Error:", err)
	}
	return resp
}

func GetReport(fileHash string) map[string]interface{} {
	var tools Utils.Tools

	combinedResult := make(map[string]interface{})
	tools_used := make(map[string]interface{}) //0 or 1
	
	analysis := SearchEs(fileHash, "vt")
	fmt.Println("GET REPORT VT ", analysis)
	if analysis != nil {
		vtAnalysis, ok := analysis["_source"].(map[string]interface{})["virustotal"].(map[string]interface{})
		fmt.Println(ok)
		tools.Vt = true
		if !ok {
			fmt.Println("[GET REPORT vt] Error: Failed to retrieve virustotal analysis")
		} else {
			combinedResult["vt"] = vtAnalysis
		}
		tools_used["vt"] = "1"
	} else {
		tools.Vt = false
		tools_used["vt"] = "0"

	}

	var mobsf_analysis map[string]interface{}
	analysis = SearchEs(fileHash, "mobsf")
	if analysis != nil {
		tools.Mobsf = true
		tools_used["mobsf"] = "1"
		data, ok := analysis["_source"].(map[string]interface{})["analysis"].(string)
		if ok {
			err := json.Unmarshal([]byte(data), &mobsf_analysis)
			if err != nil {
				fmt.Println("[GET REPORT MOBSF] Error:", err)
			}
			combinedResult["mobsf"] = mobsf_analysis
		}
	} else {
		tools.Mobsf = false
		tools_used["mobsf"] = "0"

	}

	var apkid_analysis map[string]interface{}
	analysis = SearchEs(fileHash, "apkid")
	if analysis != nil {
		tools_used["apkid"] = "1"
		tools.Apkid = true
		data := analysis["_source"].(map[string]interface{})["analysis"].(string)
		err = json.Unmarshal([]byte(data), &apkid_analysis)
		if err != nil {
			fmt.Println("[GET REPORT APKID] Error:", err)
		}
		combinedResult["apkid"] = apkid_analysis
	} else {
		tools.Apkid = false
		tools_used["apkid"] = "0"

	}

	var exodus_analysis map[string]interface{}
	analysis = SearchEs(fileHash, "exodus")
	if analysis != nil {
		data := analysis["_source"].(map[string]interface{})["analysis"].(string)
		err = json.Unmarshal([]byte(data), &exodus_analysis)
		if err != nil {
			fmt.Println("[GET REPORT EXODUS] Error:", err)
		}
		combinedResult["exodus"] = exodus_analysis
		tools.Exodus = true
		tools_used["exodus"] = "1"

	} else {
		tools.Exodus = false
		tools_used["exodus"] = "0"

	}

	SSdeepAnalysis := SearchEs(fileHash, "ssdeep")
	if SSdeepAnalysis != nil {
		data := SSdeepAnalysis["_source"].(map[string]interface{})["analysis"].(string)
		combinedResult["ssdeep"] = data
		tools.Ssdeep = true
		tools_used["ssdeep"] = "1"

	} else {
		tools.Ssdeep = false
		tools_used["ssdeep"] = "0"
	}

	analysis = SearchEs(fileHash, "quark")
	if analysis != nil {
		quark_analysis := analysis["_source"].(map[string]interface{})
		combinedResult["quark"] = quark_analysis
		tools.Quark = true
		tools_used["quark"] = "1"

	} else {
		tools.Quark = false
		tools_used["quark"] = "0"

	}

	analysis = SearchEs(fileHash, "androguard")
	if analysis != nil {
		andro_analysis := analysis["_source"].(map[string]interface{})
		combinedResult["androguard"] = andro_analysis
		tools.Androguard = true
		tools_used["andro"] = "1"

	} else {
		tools.Androguard = false
		tools_used["andro"] = "0"

	}

	UploadDataEs(fileHash, "all_tools", tools_used)

	return combinedResult
}

func ToolUsed(fileHash string) Utils.Tools {
	var tools_used Utils.Tools
	result := SearchEs(fileHash, "all_tools")
	tools := result["_source"].(map[string]interface{})

	if tools["mobsf"] == "1" {
		tools_used.Mobsf = true
	}
	if tools["vt"] == "1" {
		tools_used.Vt = true
	}
	if tools["apkid"] == "1" {
		tools_used.Apkid = true
	}
	if tools["ssdeep"] == "1" {
		tools_used.Ssdeep = true
	}
	if tools["exodus"] == "1" {
		tools_used.Exodus = true
	}
	if tools["quark"] == "1" {
		tools_used.Quark = true
	}
	if tools["andro"] == "1" {
		tools_used.Androguard = true
	}
	return tools_used

}

//Docker Command to run:
//docker run --name es01 --net elastic -p 9200:9200  -e discovery.type=single-node -v elasticsearch:/usr/share/elasticsearch/data -it docker.elastic.co/elasticsearch/elasticsearch:8.8.0
//docker rm $(docker ps -aq)
