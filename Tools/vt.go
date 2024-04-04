package Tools

// change it to "main" when making any changes and building its binary. For avoiding
// errors I've changed it to tools. Also comment godotenv piece of code in the connectToEs()
// function, then build binary file and docker image.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"example.com/m/DbCall"
)

var url1 string = "https://www.virustotal.com/api/v3/files"

var apiToken string = os.Getenv("VT_KEY")

func get_data_by_hash(client *http.Client, hash string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", url1+"/"+hash, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	fmt.Println("[VT] Response Status of getting data by hash:", resp.Status)
	if resp.Status == "404 Not Found" {
		err2 := fmt.Errorf("VT not uploaded before")
		return nil, err2
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var jsonData interface{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		return nil, err
	}
	data := jsonData.(map[string]interface{})
	final := map[string]interface{}{}
	final["virustotal"] = data
	trid, ok := final["virustotal"].(map[string]interface{})["data"].(map[string]interface{})["attributes"].(map[string]interface{})
	if ok {
		delete(trid, "trid")
		fmt.Println("[VT] deleted trid")
	} else {
		fmt.Println("[VT] not deleted trid")
	}
	return final, err
}

func upload_file(client *http.Client, file *os.File, apkpath string) string {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(apkpath))
	if err != nil {
		fmt.Println("[VT] Error creating form file:", err)
		return ""
	}
	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Println("[VT] Error copying file data:", err)
		return ""
	}
	err = writer.Close()
	if err != nil {
		fmt.Println("[VT] Error closing writer:", err)
		return ""
	}
	req, _ := http.NewRequest("POST", url1, body)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiToken)
	req.Header.Add("content-type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[VT] API ERROR UPLOADING:", err)
		return ""
	}
	defer resp.Body.Close()
	fmt.Println("[VT_UPLOAD] Response Status:", resp.Status, "! Uploaded successfully")
	res, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(res))
	jsonStr := string(res)
	var result map[string]interface{}
	err = json.Unmarshal([]byte(jsonStr), &result)
	if err != nil {
		fmt.Println("[VT] Error parsing JSON:", err)
		return ""
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		fmt.Println("[VT] Error extracting data field")
		return ""
	}

	id, ok := data["id"].(string)
	if !ok {
		fmt.Println("[VT] Error extracting id field")
		return ""
	}
	return id
}

func main() {

	DbCall.ConnectToEs()
	// os.Setenv("Filename", "lsm.apk")
	// os.Setenv("Apkpath", "/app/data/lsm.apk")
	filename := os.Getenv("Filename")
	fileHash := os.Getenv("Filehash")
	// apkpath := "./" + filename
	apkpath := "/app/data/" + fileHash + ".apk"
	filename = path.Base(filename[:len(filename)-len(path.Ext(filename))])

	fmt.Println("VIRUSTOTAL ANALYSIS")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	file, err := os.Open(apkpath)
	if err != nil {
		fmt.Println("[VT] Error opening file:", err)
		return
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		log.Fatal(err)
	}
	fileId := hex.EncodeToString(h.Sum(nil))

	file, err = os.Open(apkpath)
	if err != nil {
		fmt.Println("[VT] Error opening file:", err)
		return
	}
	defer file.Close()

	result, err2 := get_data_by_hash(client, fileId)
	fmt.Println("[VT] ERROR:", err2)
	if err2 != nil || result == nil {

		// }

		// _, ok := result["virustotal"].(map[string]interface{})["error"]
		// fmt.Println("[VT] Found: ", !ok)

		// if ok {

		fmt.Println("[VT] File has not been uploaded to VT", err2)
		id := upload_file(client, file, apkpath)
		if id != "" {
			fmt.Println(fileId + " " + id)
			time.Sleep(2 * time.Second)
			result, err := get_data_by_hash(client, id)
			if err == nil {
				DbCall.UploadDataEs(fileHash, "vt", result)
			}
		}
	} else {
		fmt.Println("[VT] File already has been uploaded to VT")
		DbCall.UploadDataEs(fileHash, "vt", result)
	}
}
