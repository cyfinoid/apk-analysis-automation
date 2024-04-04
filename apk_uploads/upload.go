package apk_uploads

import (
	"fmt"
	"net/http"
	"os"

	"example.com/m/DbCall"
	"example.com/m/Parallel"
	"example.com/m/Utils"
	"github.com/gin-gonic/gin"
)

func UploadAPK(c *gin.Context, tools Utils.Tools) {

	if Utils.AllToolsFalse(tools) {

		if c.Query("mobsf") == "1" {
			tools.Mobsf = true
		} else {
			tools.Mobsf = false
		}
		if c.Query("vt") == "1" {
			tools.Vt = true
		} else {
			tools.Vt = false
		}
		if c.Query("apkid") == "1" {
			tools.Apkid = true
		} else {
			tools.Apkid = false
		}
		if c.Query("ssdeep") == "1" {
			tools.Ssdeep = true
		} else {
			tools.Ssdeep = false
		}
		if c.Query("andro") == "1" {
			tools.Androguard = true
		} else {
			tools.Androguard = false
		}
		if c.Query("exodus") == "1" {
			tools.Exodus = true
		} else {
			tools.Exodus = false
		}
		if c.Query("quark") == "1" {
			tools.Quark = true
		} else {
			tools.Quark = false
		}
	}
	fmt.Println("[REST UPLOAD] upload function")

	file, err := c.FormFile("file")
	if err != nil {
		c.AbortWithStatusJSON(400, gin.H{"[UPLOAD]error": "No file provided"})
		return
	}
	srcFile, err := file.Open()
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"[UPLOAD]error": "Failed to open file"})
		return
	}
	defer srcFile.Close()

	var fileId string
	fileId, err = Utils.CalculateFileHash(srcFile)

	// Save the file to a directory inside the container
	dir := "./uploads"

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
	basepath := dir + "/"
	filepath := basepath + fileId + ".apk"

	_, err = os.Stat(filepath)

	if err == nil {
		fmt.Println("[APK UPLOAD] File already has been uploaded")
		//Un comment below code in final push

		// c.HTML(http.StatusOK, "home.html", gin.H{
		// 	"Hash":      fileId,
		// 	"Data":      DbCall.GetReport(fileId),
		// 	"ToolsUsed": nil,
		// })
		// return
	} else if os.IsNotExist(err) {
		if err := c.SaveUploadedFile(file, filepath); err != nil {
			fmt.Println("[APK SAVE]", err)
			c.AbortWithStatusJSON(500, gin.H{"error": "Failed to save file"})
			return
		}
	} else {
		// Handle other errors here
		fmt.Println("[APK UPLOAD]", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Failed to check file status"})
		return
	}

	filePath, err := Utils.GetAbsolutePath(fileId)

	err = Parallel.Scan(filePath, fileId, tools)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"Error": err})
	} else {
		combinedResult := make(map[string]interface{})
		combinedResult = DbCall.GetReport(fileId)

		tools := DbCall.ToolUsed(fileId)
		c.HTML(http.StatusOK, "home.html", gin.H{
			"Hash":      fileId,
			"Data":      combinedResult,
			"ToolsUsed": tools,
		})

	}
}
