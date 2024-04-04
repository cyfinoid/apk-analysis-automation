package Decompiler

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Decompile(apkPath string) {
	fmt.Println("APK TO JAVA source code extraction script")
	fmt.Println("This is a script created by Anant Shrivastava")
	fmt.Println("http://anantshri.info")
	fmt.Println("Designed and Tested on Android Tamer")
	fmt.Println("This script will work on automating the work of extracting the source code out from the apk file")

	if apkPath == "" {
		fmt.Println("APK file path is empty. Please provide the path to the APK file.")
		return
	}

	fmt.Println("Starting APK Decompile")
	JAR_KEEP := 1
	fmt.Println(apkPath)

	APK_NAME := filepath.Base(apkPath)
	c := strings.TrimSuffix(APK_NAME, ".apk")
	FULL_PTH, err := filepath.Abs(apkPath)
	if err != nil {
		panic(err)
	}
	CDIR := filepath.Dir(FULL_PTH)
	SRC_DIR := filepath.Join(CDIR, APK_NAME+"_src")
	SRC_PATH := filepath.Join(CDIR, APK_NAME+"_src")

	fmt.Println(c)
	fmt.Println(APK_NAME)
	fmt.Println("FULL_PATH", FULL_PTH)
	fmt.Println("CDIR", CDIR)

	if c == APK_NAME {
		fmt.Println("Only APK's allowed")
		return
	}

	if _, err := os.Stat(FULL_PTH); os.IsNotExist(err) {
		fmt.Println("APK file not found.")
		return
	}

	fmt.Println("Creating Output Directory")
	cmd := exec.Command("mkdir", "-p", SRC_DIR)
	_, err = cmd.Output()
	if err != nil {
		panic(err)
	}
	cmd = exec.Command("ls", "-l")
	_, err = cmd.Output()
	if err != nil {
		panic(err)
	}

	fmt.Println("Extracting files via APKTool")
	cmd = exec.Command("apktool", "decode", "-f", filepath.Join(CDIR, APK_NAME), "-o", SRC_DIR)
	_, err = cmd.Output()
	if err != nil {
		panic(err)
	}

	cmd = exec.Command("mkdir", "-p", filepath.Join(SRC_DIR, "jar"))
	_, err = cmd.Output()
	if err != nil {
		panic(err)
	}

	fmt.Println("Enjarify for decoding back to java classes")
	JAR_FILE := filepath.Join(SRC_DIR, "jar", c+"_enjarify.jar")
	cmd = exec.Command("enjarify", "-f", FULL_PTH, "-o", JAR_FILE)
	_, err = cmd.Output()
	if err != nil {
		panic(err)
	}

	fmt.Println("Decompiling via JADX Decompiler")
	cmd = exec.Command("jadx", "-d", filepath.Join(SRC_DIR, "src", "jadx"), filepath.Join(SRC_DIR, "jar", c+"_enjarify.jar"))
	cmd.Dir = filepath.Join(SRC_DIR, "jar")
	_, err = cmd.Output()
	if err != nil {
		panic(err)
	}

	// Check JAR_KEEP variable to remove jar file
	if JAR_KEEP == 0 {
		fmt.Println("removing jar file")
		enjarifyJarPath := filepath.Join(SRC_PATH, "jar", c+"_enjarify.jar")
		os.Remove(enjarifyJarPath)
		jarPath := filepath.Join(SRC_PATH, "jar")
		os.Chdir(filepath.Join(SRC_PATH, "jar"))
		os.Remove(jarPath)
	}

	// List contents of source directory
	srcDirContents, err := ioutil.ReadDir(SRC_PATH)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	for _, fileInfo := range srcDirContents {
		fmt.Println(fileInfo.Name())
	}
 
	// Change directory back to original working directory
	os.Chdir(CDIR)
	fmt.Println("All Done")
}
