package main

import (
	"fmt"
	"net/http"
	"time"

	"example.com/m/DbCall"
	"example.com/m/Parallel"
	"example.com/m/Utils"
	"example.com/m/apk_uploads"
	"github.com/gin-gonic/gin"
)

func main() {
	if !Utils.CheckContainerStatus("es01") {
		Utils.RunDockerContainer("elastic", 10)

	} else {
		fmt.Println("ElasticSearch container running")
	}
	DbCall.ConnectToEs()
	DbCall.IncreaseLimit()
	r := gin.Default()

	r.LoadHTMLGlob("templates/*.html")

	r.Static("/css", "Templates/css")
	r.Static("/images", "Templates/images")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})

	r.POST("/upload", func(c *gin.Context) {
		var selectedTools Utils.Tools

		// Bind the form data to the Tools struct
		if err := c.ShouldBind(&selectedTools); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		fmt.Println(selectedTools)
		apk_uploads.UploadAPK(c, selectedTools)
	})

	r.POST("/reupload", func(c *gin.Context) {
		hash := c.PostForm("Hash")
		var selectedTools Utils.Tools
		c.Bind(&selectedTools)
		filePath, err := Utils.GetAbsolutePath(hash)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"Error": "File not present in local server"})
		}
		fmt.Println("Hash:", filePath)

		err2 := Parallel.Scan(filePath, hash, selectedTools)
		if err2 != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"Error": err})
		} else {
			combinedResult := make(map[string]interface{})
			combinedResult = DbCall.GetReport(hash)

			tools := DbCall.ToolUsed(hash)
			c.HTML(http.StatusOK, "home.html", gin.H{
				"Hash":      hash,
				"Data":      combinedResult,
				"ToolsUsed": tools,
			})
			// c.JSON(200, combinedResult)
		}

		// apk_uploads.UploadAPK(c)
	})

	r.GET("/getReport", func(c *gin.Context) {
		fileHash := c.Query("hash")
		data := DbCall.GetReport(fileHash)
		tools := DbCall.ToolUsed(fileHash)
		if data == nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"Error": "No tool was used"})
		}
		c.HTML(http.StatusOK, "home.html", gin.H{
			"Hash":      fileHash,
			"Data":      data,
			"ToolsUsed": tools,
		})
	})

	r.GET("/list", func(c *gin.Context) {

		data := DbCall.AllIndices()
		if data == nil {
			c.HTML(http.StatusOK, "loader.html", nil)
			for data == nil {
				time.Sleep(time.Millisecond * 500)
				data = DbCall.AllIndices()
			}
			c.HTML(http.StatusOK, "apk_list.html", gin.H{
				"indices": data,
			})
		} else {
			c.HTML(http.StatusOK, "apk_list.html", gin.H{
				"indices": data,
			})
		}

	})

	r.Run(":3000")
}

// docker run -p 8080:8080 -v apk:/app/data rest
