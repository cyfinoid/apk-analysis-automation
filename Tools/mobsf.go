package Tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"example.com/m/Utils"
)

func MobsfStatic(apiToken string, apkpath string, fileId string) (map[string]interface{}, error) {

	var err error
	fmt.Println("[mobsf apitoken]", apiToken)
	fmt.Println("MOBSF ANALYSIS")
	client := &http.Client{}
	apkpath = apkpath + "/uploads/" + fileId + ".apk"
	// url := "http://mobsf:8000/api/v1/upload"
	url1 := "http://localhost:8000/api/v1/upload"

	file, err := os.Open(apkpath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil, err
	}
	defer file.Close()
	file, err = os.Open(apkpath) // Reopen the file to reset the read pointer
	if err != nil {
		fmt.Println("[MOBSF_UPLOAD] Error opening file:", err)
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(apkpath))
	if err != nil {
		fmt.Println("Error creating form file:", err)
		return nil, err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Println("Error copying file data:", err)
		return nil, err
	}
	err = writer.Close()
	if err != nil {
		fmt.Println("Error closing writer:", err)
		return nil, err
	}

	mobsf_listening := Utils.WaitMobsfForListening(0.5)
	if !mobsf_listening {
		return nil, err
	}

	req, _ := http.NewRequest("POST", url1, body)
	req.Header.Add("X-Mobsf-Api-Key", "ed459e31c40438291760e7d285892ac3d9cecd1803ed7de8033f4a26bec9ed37")
	req.Header.Add("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[MOBSF UPLOAD]", err)
		return nil, err
	}
	defer resp.Body.Close()
	fmt.Println("[MOBSF_UPLOAD] Response Status:", resp.Status)
	if resp.Status == "200 OK" {
		res, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("[MOBSF_UPLOAD]", string(res))
		var response map[string]interface{}
		err = json.Unmarshal([]byte(string(res)), &response)
		if err != nil {
			fmt.Println("[MOBSF_UPLOAD_ERROR]", err)
		}

		hash_scan, ok := response["hash"].(string)
		fmt.Println("[MOBSF_UPLOAD]", hash_scan)

		if !ok {
			fmt.Println("[MOBSF_UPLOAD] Unable to extract hash value.")
			return nil, err
		}
		fmt.Println("[MOBSF_UPLOAD]", ok)

		url2 := "http://localhost:8000/api/v1/scan"

		parm := url.Values{}
		parm.Add("scan_type", "apk")
		parm.Add("file_name", fileId+".apk")
		parm.Add("hash", hash_scan)

		req, _ := http.NewRequest("POST", url2, strings.NewReader(parm.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("X-Mobsf-Api-Key", "ed459e31c40438291760e7d285892ac3d9cecd1803ed7de8033f4a26bec9ed37")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("[MOBSF SCAN] Error posting")
			return nil, err
		}
		defer resp.Body.Close()
		fmt.Println("[MOBSF_SCAN RUNNING]")

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("[MOBSF SCAN] Error reading respose")
		}

		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if err != nil {
			fmt.Println("[MOBSF SCAN]", err)
			return nil, err
		}

		data := make(map[string]interface{})
		data["analysis"] = string(body)

		// fmt.Println("[MOBSF SCAN]", data)
		// err = Utils.StopDockerContainer("mobsf")
		// if err != nil {
		// 	fmt.Println("[MOBSF CONTAINER DIDNT STOP]", err)
		// 	return nil, err
		// }
		return data, err
	} else {
		// err = Utils.StopDockerContainer("mobsf")
		// if err != nil {
		// 	fmt.Println("[MOBSF CONTAINER DIDNT STOP]", err)
		// 	return nil, err
		// }
		return nil, err
	}

}

//docker run -it --rm -p 8000:8000 --net elastic --name mobsf opensecurity/mobile-security-framework-mobsf:latest
