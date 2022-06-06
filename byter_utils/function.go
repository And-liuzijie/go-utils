package utils

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.byted.org/aurora/be_minipro_healthy/biz/util"
	vcloud_sdk "code.byted.org/aurora/data_arch_common/vcloud-sdk"
	"code.byted.org/aurora/h5info_rpc/kitex_gen/mom_and_baby"
	"code.byted.org/aurora/h5info_rpc/src/config"
	"code.byted.org/aurora/h5info_rpc/src/utils/bizerr"
	"code.byted.org/gin/ginex"
	"code.byted.org/gopkg/env"
	"code.byted.org/gopkg/httpctx"
	"code.byted.org/gopkg/logs"
	"code.byted.org/passport/session_lib"
	"code.byted.org/videoarch/alpha-go-sdk/alpha"
	"github.com/spf13/cast"
	"moul.io/http2curl"

	//"encoding/json"
	"github.com/gin-gonic/gin"
)

func TimeSubNotice(ctx *gin.Context, title string, start time.Time) {
	tc := time.Since(start)
	util.AddGinNotice(ctx, title, tc)
}

// TimeCost ref https://blog.csdn.net/K346K346/article/details/92673425
func TimeCost(ctx *gin.Context) func() {
	startTime := time.Now()
	return func() {
		tc := time.Since(startTime)
		util.AddGinNotice(ctx, "all_tm", tc)
	}
}

// CheckParamNum check输入参数能否转为整数
func CheckParamNum(param string) (int, bool) {
	if len(param) == 0 {
		return -1, false
	}
	num, err := strconv.Atoi(strings.Trim(param, " "))
	if err != nil {
		return -1, false
	}
	return num, true
}

func CheckParamInt64(param string) (int64, bool) {
	if len(param) == 0 {
		return -1, false
	}
	num, err := strconv.ParseInt(strings.Trim(param, " "), 10, 64)
	if err != nil {
		return -1, false
	}
	return num, true
}

func CheckParamString(param string) bool {
	if len(strings.Trim(param, " ")) == 0 {
		return false
	}
	return true
}

func RetParamError(ctx *gin.Context) {
	msg := "param error"
	data := make(map[string]interface{})
	ctx.Set("rtn_code", bizerr.PARAM_ERROR)
	ctx.Set("rtn_msg", msg)
	ctx.Set("rtn_result", data)
	util.AddGinNotice(ctx, "code", bizerr.PARAM_ERROR)
	util.AddGinNotice(ctx, "msg", msg)
	logs.CtxWarn(ctx, "")
}

func BuildResMap(ctx *gin.Context, code int, msg string, data map[string]interface{}) {
	ctx.Set("rtn_code", code)
	ctx.Set("rtn_msg", msg)
	ctx.Set("rtn_result", data)
	util.AddGinNotice(ctx, "code", code)
	util.AddGinNotice(ctx, "msg", msg)
	//resJson, _ := json.Marshal(data)
	//util.AddGinNotice(ctx, "res_data", resJson)
}

func BuildResList(ctx *gin.Context, code int, msg string, data []map[string]interface{}) {
	ctx.Set("rtn_code", code)
	ctx.Set("rtn_msg", msg)
	ctx.Set("rtn_result", data)
	util.AddGinNotice(ctx, "code", code)
	util.AddGinNotice(ctx, "msg", msg)
	//resJson, _ := json.Marshal(data)
	//util.AddGinNotice(ctx, "res_data", resJson)
}

func BuildResStruct(ctx *gin.Context, code int, msg string, data interface{}) {
	ctx.Set("rtn_code", code)
	ctx.Set("rtn_msg", msg)
	ctx.Set("rtn_result", data)
	util.AddGinNotice(ctx, "code", code)
	util.AddGinNotice(ctx, "msg", msg)
}

func MethodPathNotice(ctx *gin.Context) {
	util.AddGinNotice(ctx, "method", ctx.Request.Method)
	util.AddGinNotice(ctx, "path", ctx.Request.RequestURI)
}

// CheckTime 检查时间格式是否正确
func CheckTime(timeStr string) bool {
	timeLayout := "2006-01-02 15:04:05"
	if len(strings.Split(timeStr, ":")) == 2 {
		timeLayout = "2006-01-02 15:04"
	} else if len(strings.Split(timeStr, ":")) == 1 {
		if strings.Contains(timeStr, "/") {
			timeLayout = "2006/01/02"
		} else {
			timeLayout = "2006-01-02"
		}
	}
	times, err := time.Parse(timeLayout, timeStr)
	if err != nil {
		return false
	}
	timeUnix := times.Unix()
	timeNow := time.Now().Unix()
	if timeUnix > timeNow {
		return false
	}
	return true
}

// InArrayString 检测切片包含
func InArrayString(value string, list []string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// GetDomain 根据url切出domain
func GetDomain(rawurl string) string {
	domain := ""
	urlInfo, err := url.Parse(rawurl)
	if err != nil {
		return domain
	}
	urlHostArr := strings.Split(urlInfo.Host, ".")
	if len(urlHostArr) < 2 {
		return domain
	}
	domainArr := urlHostArr[(len(urlHostArr) - 2):]
	domain = strings.Join(domainArr, ".")
	return domain
}

// MapListSort 根据map中的指定key， 对map切片排序（只支持string、int、int64类型）
func MapListSort(inputList []map[string]interface{}, key string) []map[string]interface{} {
	if len(inputList) == 0 {
		return inputList
	}
	if _, ok := inputList[0][key].(string); ok {
		for i := 0; i < len(inputList); i++ {
			for j := len(inputList) - 1; j > i; j-- {
				if inputList[j][key].(string) < inputList[j-1][key].(string) {
					tmpItem := make(map[string]interface{})
					for k, v := range inputList[j] {
						tmpItem[k] = v
					}
					for k := range inputList[j] {
						inputList[j][k] = inputList[j-1][k]
					}
					for k := range inputList[j-1] {
						inputList[j-1][k] = tmpItem[k]
					}
				}
			}
		}
	} else if _, ok := inputList[0][key].(int); ok {
		for i := 0; i < len(inputList); i++ {
			for j := len(inputList) - 1; j > i; j-- {
				if inputList[j][key].(int) < inputList[j-1][key].(int) {
					tmpItem := make(map[string]interface{})
					for k, v := range inputList[j] {
						tmpItem[k] = v
					}
					for k := range inputList[j] {
						inputList[j][k] = inputList[j-1][k]
					}
					for k := range inputList[j-1] {
						inputList[j-1][k] = tmpItem[k]
					}
				}
			}
		}
	} else if _, ok := inputList[0][key].(int64); ok {
		for i := 0; i < len(inputList); i++ {
			for j := len(inputList) - 1; j > i; j-- {
				if inputList[j][key].(int64) < inputList[j-1][key].(int64) {
					tmpItem := make(map[string]interface{})
					for k, v := range inputList[j] {
						tmpItem[k] = v
					}
					for k := range inputList[j] {
						inputList[j][k] = inputList[j-1][k]
					}
					for k := range inputList[j-1] {
						inputList[j-1][k] = tmpItem[k]
					}
				}
			}
		}
	}
	return inputList
}

// Explode2 指定分隔符切分字符串，返回前2个string
//参考：https://lbs.amap.com/api/javascript-api/guide/geometry/geometry
//计算高德坐标系两点的距离,分别输入两个点的：longitude, latitude
// CalculateDistance(116.434027, 39.941037, 116.461665, 39.941564).
func CalculateDistance(x1 float64, y1 float64, x2 float64, y2 float64) float64 {
	NfPi := 0.01745329251994329 // 弧度 pi/180

	distance := 0.0

	x1 = x1 * NfPi
	y1 = y1 * NfPi
	x2 = x2 * NfPi
	y2 = y2 * NfPi

	sin_x1 := math.Sin(x1)
	sin_y1 := math.Sin(y1)
	cos_x1 := math.Cos(x1)
	cos_y1 := math.Cos(y1)

	sin_x2 := math.Sin(x2)
	sin_y2 := math.Sin(y2)
	cos_x2 := math.Cos(x2)
	cos_y2 := math.Cos(y2)

	v0 := cos_y1*cos_x1 - cos_y2*cos_x2
	v1 := cos_y1*sin_x1 - cos_y2*sin_x2
	v2 := sin_y1 - sin_y2

	dist := math.Sqrt(v0*v0 + v1*v1 + v2*v2)

	distance = math.Asin(dist/2) * 12742001.5798544

	return distance
}

//指定分隔符切分字符串，返回前2个string
func Explode2(s, sep string) (string, string) {
	var key, value string
	arr := strings.Split(s, sep)

	if len(arr) > 0 {
		key = arr[0]
	}
	if len(arr) > 1 {
		value = arr[1]
	}
	return key, value
}

// Explode3 指定分隔符切分字符串，返回前3个string
func Explode3(s, sep string) (string, string, string) {
	var v0, v1, v2 string
	arr := strings.Split(s, sep)

	if len(arr) > 0 {
		v0 = arr[0]
	}
	if len(arr) > 1 {
		v1 = arr[1]
	}
	if len(arr) > 2 {
		v2 = arr[2]
	}
	return v0, v1, v2
}

func TrimHtml(src string) string {
	//将HTML标签全转换成小写
	re, _ := regexp.Compile("\\<[\\S\\s]+?\\>")
	src = re.ReplaceAllStringFunc(src, strings.ToLower)
	//去除STYLE
	re, _ = regexp.Compile("\\<style[\\S\\s]+?\\</style\\>")
	src = re.ReplaceAllString(src, "")
	//去除SCRIPT
	re, _ = regexp.Compile("\\<script[\\S\\s]+?\\</script\\>")
	src = re.ReplaceAllString(src, "")
	//去除所有尖括号内的HTML代码，并换成换行符
	re, _ = regexp.Compile("\\<[\\S\\s]+?\\>")
	src = re.ReplaceAllString(src, "")
	//去除连续的换行符
	//re, _ = regexp.Compile("\\s{2,}")
	//src = re.ReplaceAllString(src, "\n")
	//return strings.TrimSpace(src)
	return src
}

//获取字符串字符个数
//http://mengqi.info/html/2015/201506012300-using-golang-to-count-the-number-of-characters.html
func MbStrlen(str string) int {
	return strings.Count(str, "") - 1
}

func ArrayShiftFloat64(nums []float64) (float64, []float64) {
	if len(nums) == 0 {
		return -1, nums
	} else if len(nums) == 1 {
		return nums[0], make([]float64, 0)
	} else {
		return nums[0], nums[1:]
	}
}

func PregReplace(content string, exprArray []string) string {
	for _, expr := range exprArray {
		if re, err := regexp.Compile(expr); err == nil {
			content = re.ReplaceAllString(content, "")
		}
	}
	return content
}

func Md5(str string) string {
	data := []byte(str)
	has := md5.Sum(data)
	md5str := fmt.Sprintf("%x", has)
	return md5str
}

// SmallerFloat64 return if a < b
func SmallerFloat64(a, b float64) bool {
	return math.Min(a, b) == a &&
		math.Abs(a-b) > float64(0)
}

func GetTccConfigStruct(ctx context.Context, key string, entity interface{}) {
	ret, err := config.TccClient.Get(ctx, key)
	if err != nil {
		logs.CtxWarnsf(ctx, "failed to fetch config %s from tcc, reason: %s", key, err.Error())
		return
	}
	err = json.Unmarshal([]byte(ret), entity)
	if err != nil {
		logs.CtxWarnsf(ctx, "failed to parse tcc config %s, err: %s", key, err.Error())
		return
	}
	return
}

func contain(obj interface{}, target interface{}) (bool, error) {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true, nil
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true, nil
		}
	}
	return false, errors.New("not in array")
}

func In(o, t interface{}) bool {
	b, _ := contain(o, t)
	return b
}

func HttpRequest(ctx context.Context, conf *config.HttpConfig) ([]byte, error) {
	client := &http.Client{Timeout: conf.Timeout}
	var resp *http.Response
	var respErr error
	if conf.Method == "" {
		conf.Method = "GET"
	}
	switch strings.ToUpper(conf.Method) {
	case "GET":
		burl, err := url.Parse(conf.Host)
		if err != nil {
			return nil, err
		}
		burl.Path += conf.PathInfo
		params := url.Values{}
		for k, v := range conf.Query {
			params.Add(k, v)
		}
		burl.RawQuery = params.Encode()
		//req, err := http.NewRequest(conf.Method, burl.String(), nil)
		logs.CtxInfo(ctx, "url:[%s]", burl.String())
		req, err := httpctx.NewRequestWithContext(ctx, conf.Method, burl.String(), nil)
		if err != nil {
			logs.CtxWarn(ctx, "new request error [%s]", err.Error())
			return nil, err
		}
		for k, v := range conf.Headers {
			req.Header.Set(k, v)
		}
		resp, respErr = client.Do(req)
		curlStr, _ := http2curl.GetCurlCommand(req)
		logs.CtxInfo(ctx, "http curl: %s", curlStr)
		defer httpctx.EmitByResp(req, resp, respErr, "")
	case "POST":
		burl, err := url.Parse(conf.Host)
		if err != nil {
			return nil, err
		}
		burl.Path += conf.PathInfo
		params := url.Values{}
		for k, v := range conf.Query {
			params.Add(k, v)
		}
		burl.RawQuery = params.Encode()
		//req, err := http.NewRequest(conf.Method, burl.String(), bytes.NewReader(conf.Body))
		req, err := httpctx.NewRequestWithContext(ctx, conf.Method, burl.String(), bytes.NewReader(conf.Body))
		if err != nil {
			logs.CtxWarn(ctx, "new request error [%s]", err.Error())
			return nil, err
		}
		for k, v := range conf.Headers {
			req.Header.Set(k, v)
		}
		resp, respErr = client.Do(req)
		curlStr, _ := http2curl.GetCurlCommand(req)
		logs.CtxInfo(ctx, "http curl: %s", curlStr)
		defer httpctx.EmitByResp(req, resp, respErr, "")
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if respErr != nil {
		logs.CtxError(ctx, "backends service fail. pathinfo[%s] err:[%s]", conf.PathInfo, respErr.Error())
		return nil, respErr
	}
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logs.CtxError(ctx, "read response body fail err[%s]", err.Error())
		return nil, err
	}
	return result, nil
}

// SimpleCopyProperties struct 浅拷贝 target必须为指针
func SimpleCopyProperties(source, target interface{}) (err error) {
	// 防止意外panic
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(fmt.Sprintf("%v", e))
		}
	}()

	dstType, dstValue := reflect.TypeOf(target), reflect.ValueOf(target)
	srcType, srcValue := reflect.TypeOf(source), reflect.ValueOf(source)

	// target必须结构体指针类型
	if dstType.Kind() != reflect.Ptr || dstType.Elem().Kind() != reflect.Struct {
		return errors.New("target type should be a struct pointer")
	}

	// source必须为结构体或者结构体指针
	if srcType.Kind() == reflect.Ptr {
		srcType, srcValue = srcType.Elem(), srcValue.Elem()
	}
	if srcType.Kind() != reflect.Struct {
		return errors.New("source type should be a struct or a struct pointer")
	}

	//取具体内容
	dstType, dstValue = dstType.Elem(), dstValue.Elem()

	//属性个数
	propertyNums := dstType.NumField()

	for i := 0; i < propertyNums; i++ {
		// 属性
		property := dstType.Field(i)
		//待填充属性值
		propertyValue := srcValue.FieldByName(property.Name)

		if !propertyValue.IsValid() || property.Type != propertyValue.Type() {
			continue
		}
		if dstValue.Field(i).CanSet() {
			dstValue.Field(i).Set(propertyValue)
		}
	}
	return nil
}

// GetSessionUserID 通过登录态获取用户ID
func GetSessionUserID(c *gin.Context) int64 {
	var cookieStr string
	cooks := c.Request.Cookies()
	if len(cooks) > 0 {
		for _, c := range cooks {
			cookieStr = cookieStr + c.Name + "=" + c.Value + ";"
		}
	}
	userID, err := session_lib.GetUserId(c)
	if userID == 0 && !env.IsProduct() { // 没获取到用户信息，并且不是线上环境
		userIDStr := c.GetHeader("user-id")
		userID, _ = strconv.ParseInt(userIDStr, 10, 64)
		//if userID == 0 {
		//	userIDCookieStr, _ := c.Cookie("user_id")
		//	userID = cast.ToInt64(userIDCookieStr)
		//	logs.Info("cookie did %s", userIDCookieStr)
		//}
		if userID != 0 {
			err = nil
		}
	}
	if err != nil {
		logs.CtxError(c, "--"+ginex.PSM()+" 获取userid信息失败： "+err.Error())
		return 0
	}
	logs.CtxNotice(c, "cookieStr %v | userID %v", cookieStr, userID)
	return userID
}

// GetSessionDeviceID 通过登录态获取用户DeviceID
func GetSessionDeviceID(c *gin.Context) int64 {
	var cookieStr string
	cooks := c.Request.Cookies()
	if len(cooks) > 0 {
		for _, c := range cooks {
			cookieStr = cookieStr + c.Name + "=" + c.Value + ";"
		}
	}
	deviceID, err := session_lib.GetDeviceId(c)
	if deviceID == 0 && !env.IsProduct() { // 没获取到用户信息，并且不是线上环境
		didStr := c.GetHeader("device-id")
		deviceID, _ = strconv.ParseInt(didStr, 10, 64)
		if deviceID != 0 {
			err = nil
		}
	}
	if deviceID == 0 {
		didCookieStr, _ := c.Cookie("bd_device_id")
		deviceID = cast.ToInt64(didCookieStr)
		logs.Info("cookie did %s", didCookieStr)
	}
	if err != nil {
		logs.CtxError(c, "--"+ginex.PSM()+" 获取did信息失败： "+err.Error())
		//c.Abort()
		return 0
	}
	logs.CtxNotice(c, "cookieStr %v | deviceID %v", cookieStr, deviceID)
	return deviceID
}

// GetDoctorEndorsement 工具-获取医生背书
func GetDoctorEndorsement(ctx context.Context, needKey string) *mom_and_baby.Endorsement {
	var endorsementMap = make(map[string]*mom_and_baby.Endorsement)
	var endorsementList = make([]*mom_and_baby.Endorsement, 0)
	GetTccConfigStruct(ctx, config.TccDoctorEndorsementKey, &endorsementList)
	for _, endorsement := range endorsementList {
		if endorsement != nil {
			endorsementMap[endorsement.Key] = endorsement
		}
	}
	endorsements := endorsementMap[needKey]
	return endorsements
}

// GetImageXURL 获取图片url
func GetImageXURL(ctx context.Context, uri, tpl string, withExpire time.Duration) string {
	if len(uri) == 0 {
		return ""
	}
	vcloud := config.Config.Vcloud
	if len(tpl) == 0 || !env.IsProduct() {
		tpl = vcloud.Tpl
	}
	logs.Info("ImagexMainDomain%s", vcloud.ImagexMainDomain)
	param := &vcloud_sdk.ImageXURLsParam{
		MainDomain: vcloud.ImagexMainDomain,
		Uri:        uri,
		Tpl:        tpl,
		Format:     alpha.FORMAT_ORIGINAL,
		WithExpire: withExpire,
	}
	var imgUrl *alpha.ImgUrl
	var err error
	if env.IsProduct() {
		imgUrl, err = vcloud_sdk.GetImageXURLs(ctx, param)
	} else {
		imgUrl, err = vcloud_sdk.GetImageXInnerURLs(ctx, param)
	}
	if err != nil {
		logs.CtxError(ctx, "utils -> GetImageXURL error: %+v", err)
		return ""
	}
	return imgUrl.MainUrl
}

// GetVideoPath 根据vid获取url
func GetVideoPath(ctx context.Context, vid string) string {
	//logs.Info("配置参数：ak-%s sk-%s psm-%s", config.Config.Vcloud.IamAk, config.Config.Vcloud.IamSk, config.Config.Vcloud.Psm)
	param := &vcloud_sdk.PlayInfoParam{
		VID: vid,
		Ak:  config.Config.Vcloud.IamAk,
		Sk:  config.Config.Vcloud.IamSk,
		Psm: config.Config.Vcloud.Psm,
	}
	data, err := vcloud_sdk.GetPlayInfo(ctx, param)
	if err != nil {
		logs.CtxError(ctx, "GetVidToVideo->GetPlayInfo error: %+v", err)
	}
	logs.CtxInfo(ctx, "GetVidToVideo:%+v", data)
	playInfo := data[vid]
	if playInfo == nil || len(playInfo.VideoInfos) == 0 {
		return ""
	}
	var videoUrl string
	if len(playInfo.VideoInfos) > 0 && len(playInfo.VideoInfos[0].MainUrl) > 0 {
		videoUrl = playInfo.VideoInfos[0].MainUrl
	} else {
		videoUrl = playInfo.OriginalVideoInfo.MainUrl
	}
	if len(videoUrl) > 0 {
		videoUrl = strings.ReplaceAll(videoUrl, "http://", "https://")
	}
	return videoUrl
}

func GetVideoToken(ctx context.Context, vid string) string {
	//logs.Info("配置参数：ak-%s sk-%s psm-%s", config.Config.Vcloud.IamAk, config.Config.Vcloud.IamSk, config.Config.Vcloud.Psm)
	param := &vcloud_sdk.PlayInfoTokenParam{
		VID: vid,
		Ak:  config.Config.Vcloud.IamAk,
		Sk:  config.Config.Vcloud.IamSk,
	}
	token, err := vcloud_sdk.GetPlayInfoToken(ctx, param)
	if err != nil {
		logs.CtxError(ctx, "GetVidToVideo->GetPlayInfo error: %+v", err)
		return ""
	}
	return token
}

func JsonToMap(ctx context.Context, jsonData string) (map[string]string, error) {
	jsonMap := make(map[string]string)
	err := json.Unmarshal([]byte(jsonData), &jsonMap)
	if err != nil {
		logs.CtxError(ctx, "jsonToMap json反序列化失败err%s", err.Error())
		return jsonMap, err
	}
	return jsonMap, nil
}

func JsonLog(ctx context.Context, i interface{}) string {
	jsonStr, err := json.Marshal(i)
	if err != nil {
		logs.CtxError(ctx, "json log 序列化失败")
		return ""
	}
	return string(jsonStr)
}

func IsNum(s string) bool { _, err := strconv.ParseFloat(s, 64); return err == nil }

func Transfer(num int) string {
	chineseMap := []string{"", "十", "百", "千", "万", "十", "百", "千", "亿", "十", "百", "千"}
	chineseNum := []string{"零", "一", "二", "三", "四", "五", "六", "七", "八", "九"}
	listNum := []int{}
	for ; num > 0; num = num / 10 {
		listNum = append(listNum, num%10)
	}
	n := len(listNum)
	chinese := ""
	//注意这里是倒序的
	for i := n - 1; i >= 0; i-- {
		chinese = fmt.Sprintf("%s%s%s", chinese, chineseNum[listNum[i]], chineseMap[i])
	}
	//注意替换顺序
	for {
		copychinese := chinese
		copychinese = strings.Replace(copychinese, "零万", "万", 1)
		copychinese = strings.Replace(copychinese, "零亿", "亿", 1)
		copychinese = strings.Replace(copychinese, "零十", "零", 1)
		copychinese = strings.Replace(copychinese, "零百", "零", 1)
		copychinese = strings.Replace(copychinese, "零千", "零", 1)
		copychinese = strings.Replace(copychinese, "零零", "零", 1)
		copychinese = strings.Replace(copychinese, "零圆", "圆", 1)

		if copychinese == chinese {
			break
		} else {
			chinese = copychinese
		}
	}

	return chinese
}
