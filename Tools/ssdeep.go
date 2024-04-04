package Tools

import (
	"fmt"
	"os"

	"github.com/glaslos/ssdeep"
)

func CalculateFuzzyHash(filepath string, filename string) string {



	f, err := os.Open(filepath + "/uploads/" + filename+ ".apk")
	
	fmt.Println("[SSDEEP]", filename)
	if err != nil {
		fmt.Println("[SSDEEP ERROR]", err)
	}
	defer f.Close()

	h, err := ssdeep.FuzzyFile(f)
	if err != nil {
		fmt.Println("[SSDEEP ERROR]", err)

	}
	return h
}
