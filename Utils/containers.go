package Utils

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func CheckContainerStatus(name string) bool {
	cmd := exec.Command("docker", "ps", "--filter", "name="+name, "--format", "{{.Names}}")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running docker ps command:", err)
		return false
	}

	containers := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(containers) > 0 && containers[0] == name {
		fmt.Println("Container '" + name + "' is running.")
		return true
	} else {
		fmt.Println("Container '" + name + "' is not running.")
		return false
	}
}

func RunDockerContainer(name string, timeout int) {
	var cmd *exec.Cmd
	// pwd, errx := os.Getwd()
	// if errx != nil {
	// 	fmt.Println("[UTILS DOCKER CONTAINER RUN]", errx)
	// }

	// mobsfCacheDir := filepath.Join(pwd, "Tools/MobsfCache")
	//"-v", mobsfCacheDir+":/home/mobsf/.MobSF",
	if name == "mobsf" {
		// cmd = exec.Command("docker", "run", "--rm", "-p", "8000:8000",
		// 	"--name", "mobsf", "opensecurity/mobile-security-framework-mobsf")
		cmd = exec.Command("docker", "run", "--rm", "-p", "8000:8000",
		"--name", "mobsf", "mobsf")
	} else if name == "elastic" {
		cmd = exec.Command("docker-compose", "--env-file", "./rest.env", "up", "-d")

	} else {
		return
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Create a context with a timeout of 10 seconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	err := cmd.Start()
	if err != nil {
		fmt.Println("[RUNNING "+name+" CONTAINER]", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Timeout occurred, kill the command
		cmd.Process.Kill()
		fmt.Println("[RUNNING CONTAINER] Command timed out.")
	case err := <-done:
		if err != nil {
			fmt.Println("[RUNNING "+name+" CONTAINER]", err)
		}
	}
}

func WaitMobsfForListening(timeout float32) bool {
	timeLimit := 50 * time.Second
	startTime := time.Now()
	for {
		time.Sleep(time.Duration(timeout*1000) * time.Millisecond)
		elapsed := time.Since(startTime)
		if elapsed >= timeLimit {
			fmt.Println("[MOBSF LISTENING] Time limit exceeded")
			break
		}
		cmd := exec.Command("sh", "-c", `docker logs mobsf 2>&1 | grep "Listening at"`)
		output, err := cmd.Output()
		if err != nil {
			fmt.Println("[MOBSF LISTENING] NOT LISTENING", err, string(output))

		}
		if strings.Contains(string(output), "Listening at") {
			fmt.Println("[MOBSF LISTENING] true TIME TAKEN TO LISTEN:", elapsed)
			return true
		}

	}

	return false
}

func GetMobsfToken() string {
	cmd := exec.Command("sh", "-c", `docker logs mobsf 2>&1 | grep "REST API Key"`)

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[MOBSF TOKEN] Error running command:", err)
		return "0"
	}

	lines := strings.Split(string(output), "\n")
	firstLine := strings.TrimSpace(lines[0])
	parts := strings.Split(firstLine, ":")
	apiKey := strings.TrimSpace(parts[1])
	fmt.Println(apiKey)

	return apiKey
}

func CheckImageDocker(imageName string) bool {
	cmd := exec.Command("docker", "images")

	// Capture the command output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	// Convert output to string
	outputString := string(output)

	// Check if the image is present in the output
	if strings.Contains(outputString, imageName) {
		fmt.Printf("Docker image '%s' is present.\n", imageName)
		return true
	} else {
		fmt.Printf("Docker image '%s' is not present.\n", imageName)
		return false
	}

}

func BuildImage(imageName string, dockerfilePath string) {
	// dockerfilePath := "./Tools/Dockerfile"
	cmd := exec.Command("docker", "build", "-t", imageName, "-f", dockerfilePath, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Docker image built successfully.")
}

func DirEnv(envFile string) string {
	currentDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	for {
		goModPath := filepath.Join(currentDir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			break
		}

		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			panic(fmt.Errorf("go.mod not found"))
		}
		currentDir = parent
	}
	return filepath.Join(currentDir, envFile)
}

func GetAbsolutePath(filename string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(wd)
	if err != nil {
		return "", err
	}

	return absPath, nil
}

func CalculateFileHash(file io.Reader) (string, error) {
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	return hashString, nil
}

func StopDockerContainer(name string) error {
	// Construct the docker stop command
	cmd := exec.Command("docker", "rm", "-f", name)

	// Execute the command
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("["+name+"] failed to stop Docker container:", err)
	}

	return err
}
