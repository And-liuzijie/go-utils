package excel

import (
	"code.byted.org/gopkg/logs"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
)

func getSql() {
	f, err := excelize.OpenFile("/Users/bytedance/GolandProjects/go-utils/excel/小荷-临床招募项目字段要求20221031 副本.xlsx")
	if err != nil {
		logs.Error("读取文件错误 err = %s", err.Error())
	}
	rows := f.GetRows("项目数据")

	if err != nil {
		logs.Error("获取row err = %s", err.Error())
	}
	for _, row := range rows {
		fmt.Printf("%s", row[5])
		//for _, line := range row {
		//	fmt.Printf("\t%s", line)
		//}
	}
}
