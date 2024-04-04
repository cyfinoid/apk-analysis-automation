package Parallel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"example.com/m/DbCall"
	"example.com/m/Tools"
	"example.com/m/Utils"
)

func Scan(filepath string, fileHash string, tools Utils.Tools) error {

	var wg sync.WaitGroup
	// var apkid, vt, exodus, ssdeep, mobsf bool
	apkid_run := tools.Apkid
	mobsf_run := tools.Mobsf
	vt_run := tools.Vt
	ssdeep_run := tools.Ssdeep
	exodus_run := tools.Exodus
	quark_run := tools.Quark
	andro_run := tools.Androguard
	fmt.Println("[PARALLEL FUNC SELECTED TOOLS]", tools)

	ch_apkid := make(chan map[string]interface{})
	ch_exodus := make(chan map[string]interface{})
	ch_vt := make(chan map[string]interface{})
	ch_mobsf := make(chan map[string]interface{})
	ch_ssdeep := make(chan string)
	ch_quark := make(chan map[string]interface{})
	ch_andro := make(chan map[string]interface{})

	var err error

	if vt_run {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if !Utils.CheckImageDocker("vt") {
				Utils.BuildImage("vt", "./Tools/Dockerfile")
			}
			cmd := exec.Command("docker", "run", "--net", "elastic", "-e",
				"Filehash="+fileHash, "--env-file", "./rest.env", "-v", filepath+"/uploads:/app/data", "vt")

			_, err2 := cmd.CombinedOutput()
			if err2 != nil {
				fmt.Println("[PARALLEL VT]", err2)
				err = fmt.Errorf("VT CRASHED")
				ch_vt <- nil
				return
			}

			// fmt.Println("[PARALLEL VT] ", string(res))

			analysis := DbCall.SearchEs(fileHash, "vt")
			if analysis == nil {
				err = fmt.Errorf("VT CRASHED")
				ch_vt <- nil
				return
			}
			data := analysis["_source"].(map[string]interface{})["virustotal"].(map[string]interface{})
			ch_vt <- data

		}()

	}

	if mobsf_run {
		wg.Add(1)
		go func() {
			// startTime := time.Now().Local()
			defer wg.Done()
			var MobsfToken string
			if Utils.CheckContainerStatus("mobsf") {
				MobsfToken = Utils.GetMobsfToken()
				fmt.Println(MobsfToken)
			} else {
				mobsf_container_name := "opensecurity/mobile-security-framework-mobsf"
				// mobsf_container_name := "mobsf"
				Utils.RunDockerContainer(mobsf_container_name, 6)
				MobsfToken = Utils.GetMobsfToken()
				fmt.Println("[MOBSF TOKEN]", MobsfToken)
			}
			if MobsfToken != "0" {
				fmt.Println("MOBSF API KEY Extracted")
				data, err2 := Tools.MobsfStatic(MobsfToken, filepath, fileHash)
				if err2 != nil {
					ch_mobsf <- nil
					return
				}
				// elapsed := time.Since(startTime)
				// data["time"] = elapsed.Seconds()
				DbCall.UploadDataEs(fileHash, "mobsf", data)

				var mobsf_analysis map[string]interface{}
				MapString, ok := data["analysis"].(string)
				if !ok {
					ch_mobsf <- nil
					return
				}
				err2 = json.Unmarshal([]byte(MapString), &mobsf_analysis)
				if err2 != nil {
					fmt.Println("[PARALLEL MOBSF] Error:", err2)
					ch_mobsf <- nil
					return
				}

				ch_mobsf <- mobsf_analysis
			} else {
				ch_mobsf <- nil
			}

		}()

	}

	if apkid_run {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("/bin/bash", "./Tools/apkid.sh", "-j", filepath+"/uploads/"+fileHash+".apk")
			res, err2 := cmd.CombinedOutput()
			if err2 != nil {
				fmt.Println("[PARALLEL APKID]", err2)
				ch_apkid <- nil
			}
			result := make(map[string]interface{})
			result["analysis"] = string(res)
			DbCall.UploadDataEs(fileHash, "apkid", result)

			var apkid_analysis map[string]interface{}
			err2 = json.Unmarshal([]byte(string(res)), &apkid_analysis)
			if err2 != nil {
				fmt.Println("[PARALLEL APKID] Error:", err2)
				ch_apkid <- nil
			} else {
				ch_apkid <- apkid_analysis
			}

		}()

	}

	if exodus_run {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("[running exodus]")

			cmd := exec.Command("docker", "run", "--net", "elastic", "-v", filepath+"/uploads:/app", "-i", "exodusprivacy/exodus-standalone", "-j", "/app/"+fileHash+".apk")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err2 := cmd.Run()
			if err != nil {
				fmt.Println("[EXODUS ERROR]", err2.Error())
				ch_exodus <- nil
				return
			}
			output, _ := string(stdout.Bytes()), string(stderr.Bytes())

			var output_filtered string
			for i := 29; i < 37; i++ {
				if strings.Contains(string(output), "Requested API level "+strconv.Itoa(i)+" is larger than maximum we have, returning API level 28 instead.") {
					output_filtered = strings.Replace(string(output), "Requested API level "+strconv.Itoa(i)+" is larger than maximum we have, returning API level 28 instead.\n", "", -1)
					break
				}
				output_filtered = string(output)
			}

			result := make(map[string]interface{})
			result["analysis"] = output_filtered
			DbCall.UploadDataEs(fileHash, "exodus", result)

			var exodus_analysis map[string]interface{}
			data := result["analysis"].(string)
			err2 = json.Unmarshal([]byte(data), &exodus_analysis)
			if err != nil {
				fmt.Println("[PARALLEL EXODUS] Error:", err)
				ch_exodus <- nil
			} else {
				ch_exodus <- exodus_analysis
			}
		}()

	}

	if ssdeep_run {
		wg.Add(1)
		go func() {
			defer wg.Done()

			fuzzyHash := Tools.CalculateFuzzyHash(filepath, fileHash)
			result := make(map[string]interface{})
			if fuzzyHash != "" {
				result["analysis"] = fuzzyHash
				DbCall.UploadDataEs(fileHash, "ssdeep", result)
				data := result["analysis"].(string)
				ch_ssdeep <- data

			} else {
				ch_ssdeep <- ""
			}

		}()
	}

	if quark_run {
		wg.Add(1)
		go func() {
			defer wg.Done()

			temp_filepath := "./Tools/quark/" + fileHash + "json"
			rulefile := "rules_sec"
			cmd := exec.Command("sh", "-c", `docker run -v $(pwd):/tmp --name quark --rm -t quark bash | 
			cd /tmp |
			quark -a ./uploads/`+fileHash+`.apk -s -r "./Tools/quark/`+rulefile+`" -o`+temp_filepath)
			// cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Println("[QUARK]", err)
				ch_quark <- nil
				return
			}

			fileContent, err2 := ioutil.ReadFile(temp_filepath)
			if err2 != nil {
				fmt.Println("Failed to read file:", err)
				ch_quark <- nil
				return
			}
			var originalData map[string]interface{}
			err2 = json.Unmarshal(fileContent, &originalData)
			if err != nil {
				fmt.Println("[QUARK] Failed to parse JSON:", err)
				ch_quark <- nil
				return
			}
			// Create a new optimized map
			optimizedData := make(map[string]interface{})
			optimizedData["md5"] = originalData["md5"]
			optimizedData["apk_filename"] = originalData["apk_filename"]
			optimizedData["size_bytes"] = originalData["size_bytes"]
			optimizedData["threat_level"] = originalData["threat_level"]
			optimizedData["total_score"] = originalData["total_score"]

			// Create a new crimes array with only required fields
			originalCrimes := originalData["crimes"].([]interface{})
			optimizedCrimes := make([]map[string]interface{}, 0)

			for _, crime := range originalCrimes {
				crimeData := crime.(map[string]interface{})
				if crimeData["confidence"] == "100%" {
					optimizedCrimes = append(optimizedCrimes, map[string]interface{}{
						"crime":      crimeData["crime"],
						"confidence": crimeData["confidence"],
					})
				}
			}

			optimizedData["crimes"] = optimizedCrimes

			cmd = exec.Command("rm", temp_filepath)
			if err2 := cmd.Run(); err2 != nil {
				fmt.Println("[QUARK]", err2)
				return
			} else {
				DbCall.UploadDataEs(fileHash, "quark", optimizedData)
				ch_quark <- optimizedData
			}

		}()

	}
	if andro_run {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !Utils.CheckImageDocker("androguard") {
				Utils.BuildImage("androguard", "./Tools/androguard/Dockerfile")
			}
			cmd := exec.Command("docker", "run", "--net", "elastic", "-e", "Filename="+fileHash+".apk",
				"-v", filepath+"/uploads:/app/data", "androguard")

			output, err2 := cmd.CombinedOutput()
			if err2 != nil {
				fmt.Println("[PARALLEL ANDROGUARD]", err2)
				ch_andro <- nil
				return
			}
			var output_filtered string
			for i := 29; i < 37; i++ {
				if strings.Contains(string(output), "Requested API level "+strconv.Itoa(i)+" is larger than maximum we have, returning API level 28 instead.") {
					output_filtered = strings.Replace(string(output), "Requested API level "+strconv.Itoa(i)+" is larger than maximum we have, returning API level 28 instead.\n", "", -1)
					break
				}
				output_filtered = string(output)
			}
			output_filtered = strings.ReplaceAll(output_filtered, "'", `"`)
			output_filtered = strings.ReplaceAll(output_filtered, "None", "null")

			result := make(map[string]interface{})
			err2 = json.Unmarshal([]byte(output_filtered), &result)
			if err2 != nil {
				fmt.Println("[PARALLEL ANDRO (line 302)]Error:", err, output_filtered)
				ch_andro <- nil
				return
			}
			fmt.Println("[PARALLEL ANDRO]", result)

			DbCall.UploadDataEs(fileHash, "androguard", result)
			ch_andro <- result

		}()
	}
	//// REDUNDANT BUT NECESSARY
	combinedResult := make(map[string]interface{})
	if apkid_run {
		combinedResult["apkid"] = <-ch_apkid
		if combinedResult["apkid"] == nil {

			err = fmt.Errorf("apkid CRASHED")
		}
		close(ch_apkid)
	}
	if exodus_run {
		combinedResult["exodus"] = <-ch_exodus
		if combinedResult["exodus"] == nil {
			err = fmt.Errorf("exodus CRASHED")
		}
		close(ch_exodus)
	}
	if ssdeep_run {
		combinedResult["ssdeep"] = <-ch_ssdeep
		if combinedResult["ssdeep"] == nil {
			err = fmt.Errorf("ssdeep CRASHED")
		}
		close(ch_ssdeep)
	}
	if vt_run {
		combinedResult["vt"] = <-ch_vt
		if combinedResult["vt"] == nil {
			err = fmt.Errorf("VT CRASHED")
		}
		close(ch_vt)
	}
	if mobsf_run {
		combinedResult["mobsf"] = <-ch_mobsf
		if combinedResult["mobsf"] == nil {
			err = fmt.Errorf("MOBSF CRASHED")
		}
		close(ch_mobsf)
	}
	if quark_run {
		combinedResult["quark"] = <-ch_quark
		if combinedResult["quark"] == nil {
			err = fmt.Errorf("quark CRASHED")
		}
		close(ch_quark)
	}
	if andro_run {
		combinedResult["androguard"] = <-ch_andro
		if combinedResult["androguard"] == nil {
			err = fmt.Errorf("androguard CRASHED")
		}
		close(ch_andro)
	}

	return err

}
