package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/redis/go-redis/v9"
)

var BASE_URL string = "http://localhost:8080/upload"

//maxProcessingCount number represents the number of apk files that can be processed parallely.
//Each apk file is passed serially to every tool.
const (
	maxProcessingCount = 8
)

func main() {
	ctx := context.Background()

	//INPUT SOURCE DIRECTORY IN THE BELOW FUNCTION ARGS
	// err := renameAndCopyApkFiles("--input--", "./uploads")
	// if err != nil {
	// 	panic(err)
	// }

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default database
	})

	var wg sync.WaitGroup

	dir, err := os.ReadDir("./uploads")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, entry := range dir {
		if !entry.IsDir() {
			fileName := entry.Name()
			extension := filepath.Ext(fileName)
			fileNameWithoutExt := fileName[:len(fileName)-len(extension)]
			if err := client.LPush(ctx, "apk_hashes", fileNameWithoutExt).Err(); err != nil {
				fmt.Println("Error pushing to Redis queue:", err)
				panic(err)
			}
			fmt.Println("Redis Queue updated!")
		}
	}

	for {
		
		length, err := client.LLen(ctx, "apk_hashes").Result()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		if length == 0 {
			fmt.Println("Queue is empty")
			break
		} else {
			fmt.Println("LENGTH OF QUEUE:", length)
		}

		numToProcess := maxProcessingCount
		if length < int64(maxProcessingCount) {
			numToProcess = int(length)
		}

		semaphore := make(chan struct{}, maxProcessingCount)

		for i := 0; i < numToProcess; i++ {
			
			data, err := client.RPop(ctx, "apk_hashes").Result()
			if err != nil {
				log.Printf("Error popping from the queue: %v", err)
				break
			}

			wg.Add(1)
			semaphore <- struct{}{} 
			go func(data string) {
				defer func() {
					<-semaphore 
					wg.Done()
				}()
				worker(ctx, &wg, data, client)
			}(data)
			
		}

	}
	wg.Wait()
}

func worker(ctx context.Context, wg *sync.WaitGroup, hash string, client *redis.Client) {
	

	urls := []string{
		//PRIORITIZED
		"?ssdeep=1",
		"?apkid=1",
		"?andro=1",
		"?exodus=1",
		"?vt=1",
		"?mobsf=1",
		"?quark=1",
	}

	results := make(chan string)
	filepath := "./uploads/"
	for _, url := range urls {
		fetchAPI(wg, ctx, BASE_URL+url, results, filepath+hash+".apk", hash)
	}

	for i := 0; i < len(urls); i++ {
		fmt.Println("PRINTING RESULT OF API CALL")
	}
}


func fetchAPI(wg *sync.WaitGroup, ctx context.Context, url string, results chan<- string, filepath string, hash string) {
	// defer wg.Done()
	// Create a buffer to store the file data
	fmt.Println("FETCHING API")
	var bodyBuf bytes.Buffer
	bodyWriter := multipart.NewWriter(&bodyBuf)

	// Open the file from a local directory
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Println("Error opening the file: %s", err.Error())
		// results <- fmt.Sprintf("Error opening the file: %s", err.Error())
		return
	}
	fmt.Println("File opened")
	// defer file.Close()

	// Create a form field for the file
	fileWriter, err := bodyWriter.CreateFormFile("file", hash)
	if err != nil {
		fmt.Println("Error creating form field: %s", err.Error())
		// results <- fmt.Sprintf("Error creating form field: %s", err.Error())
		return
	}

	// Copy the file data into the form field
	_, err = io.Copy(fileWriter, file)
	if err != nil {
		fmt.Println("Error copying file data: %s", err.Error())
		// results <- fmt.Sprintf("Error copying file data: %s", err.Error())
		return
	}

	// Close the multipart writer
	bodyWriter.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", url, &bodyBuf)
	if err != nil {
		fmt.Println("Error creating request for %s: %s", url, err.Error())
		// results <- fmt.Sprintf("Error creating request for %s: %s", url, err.Error())
		return
	}

	req.Header.Set("Content-Type", bodyWriter.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request to %s: %s", url, err.Error())
		// results <- fmt.Sprintf("Error making request to %s: %s", url, err.Error()
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response from %s: %d", url, resp.StatusCode)
	// results <- fmt.Sprintf("Response from %s: %d", url, resp.StatusCode)
}

func renameAndCopyApkFiles(srcDir, destDir string) error {
	files, err := filepath.Glob(filepath.Join(srcDir, "*.apk"))
	if err != nil {
		return err
	}

	for _, file := range files {
		hash, err := generateFileHash(file)
		if err != nil {
			return err
		}

		newName := hash + ".apk"
		destPath := filepath.Join(destDir, newName)

		srcFile, err := os.Open(file)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		destFile, err := os.Create(filepath.Join(destDir, newName))
		if err != nil {
			return err
		}
		defer destFile.Close()

		if _, err := io.Copy(destFile, srcFile); err != nil {
			return err
		}

		fmt.Printf("Copied %s to %s\n", file, destPath)
	}

	return nil
}

func generateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	return hashString, nil
}
