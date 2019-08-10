package main

import (
	"encoding/json"
	"fmt"
	"github.com/chr4/pwgen"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/tidwall/gjson"
	"gopkg.in/robfig/cron.v3"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const (
	ADDR           = ":12340"
	ConfigJsonPath = "/etc/shadowsocks/config.json"
	CmdSsrRestart  = "/etc/init.d/shadowsocks"
	RootName       = "rtl"
	SsrMethod      = "chacha20"
	SsrProtocol    = "origin"
	SsrObfs        = "plain"
)

const (
	UserTypeSu = iota
	UserTypeNormal
)

var (
	IsReleaseMode = false
	db            *gorm.DB
	err           error
)

type UserInfo struct {
	ID         uint   `json:"id"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	Port       string `json:"port"`
	Token      string `json:"token"`
	Type       uint   `json:"type"`
	CreateTime string `json:"create_time"`
	UpdateTime string `json:"update_time"`
}

type ShadowsocksConfig struct {
	Remarks         string `json:"remarks"`
	SubscriptionUrl string `json:"subscription_url"`
	Server          string `json:"server"`
	ServerPort      string `json:"server_port"`
	Password        string `json:"password"`
	Method          string `json:"method"`
	Protocol        string `json:"protocol"`
	Obfs            string `json:"obfs"`
	CreateTime      string `json:"create_time"`
	UpdateTime      string `json:"update_time"`
}

func init() {
	ginLog("[init]", "gin mode: "+gin.Mode())
	IsReleaseMode = gin.Mode() == gin.ReleaseMode

	// Logging to a file.
	f, _ := os.Create("gin.log")
	if IsReleaseMode {
		// Disable Console Color, you don't need console color when writing the logs to file.
		//gin.DisableConsoleColor()
		gin.DefaultWriter = io.MultiWriter(f)
	} else {
		gin.ForceConsoleColor()
		// Use the following code if you need to write the logs to file and console at the same time.
		gin.DefaultWriter = io.MultiWriter(f, os.Stdout)
	}

	initDb()
}

func main() {
	defer db.Close()
	startTimer()

	r := gin.Default()

	log(r)

	makeApi(r)

	r.Run(ADDR) // listen and serve on 0.0.0.0:8080
}

func startTimer() {
	nyc, _ := time.LoadLocation("Asia/Shanghai")
	var c = cron.New(cron.WithSeconds(), cron.WithLocation(nyc))
	id, e := c.AddFunc("@daily", func() {
		ginLog("[cron]", "Every day ssrRestart")
		ssrRestart()
	})
	if e != nil {
		ginLog("[cron]", "添加每天定时重启任务失败: "+e.Error())
	}
	//Seconds Minutes Hours (Day of month) Month (Day of week)
	id1, e := c.AddFunc("0 0 1 30 * *", func() {
		ginLog("[cron]", "Every monthly")
		//TODO update all port

	})
	if e != nil {
		ginLog("[cron]", "添加每月定时修改端口任务失败: "+e.Error())
	}
	c.Start()
	ginLog("[cron]", "schedule EntryID: "+fmt.Sprintf("%d, %d", id, id1))
}

func log(r *gin.Engine) {
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {

		// 你的自定义格式
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))
	r.Use(gin.Recovery())
}

func makeApi(r *gin.Engine) {

	v1 := r.Group("/v1")
	{
		pingEndpoint := func(c *gin.Context) {
			c.IndentedJSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		}
		v1.GET("/ping", pingEndpoint)

		//管理者添加用户
		v1.GET("/user/add/:token/:name", func(c *gin.Context) {
			name := c.Param("name")
			token := c.Param("token")
			var userInfo UserInfo
			db.First(&userInfo, &UserInfo{Token: token})
			if userInfo.Name != "" && userInfo.Type == UserTypeSu {
				var userInfo UserInfo
				db.First(&userInfo, &UserInfo{Name: name})
				if userInfo.Name == name {
					c.IndentedJSON(http.StatusOK, gin.H{"status": "exist"})
					return
				}
				ginLog("[ManagerAction]", "create Normal user "+name)

				pwd := pwgen.AlphaNum(10)
				user := CreateUser(name, pwd, UserTypeNormal)
				var portPwd = make(map[string]string)
				portPwd[user.Port] = pwd
				e := HandleConfigJson(ConfigJsonPath, portPwd, true)
				if e != nil {
					c.IndentedJSON(http.StatusOK, gin.H{"code": "0", "msg": e.Error()})
					return
				}

				c.IndentedJSON(http.StatusOK, gin.H{"code": "1", "msg": ssrRestart()})
			} else {
				c.IndentedJSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
			}
		})
		//管理者删除用户
		v1.GET("/user/delete/:token/:name", func(c *gin.Context) {
			name := c.Param("name")
			token := c.Param("token")
			var userInfo UserInfo
			db.First(&userInfo, &UserInfo{Token: token})
			if userInfo.Name != "" && userInfo.Type == UserTypeSu {
				var userInfo UserInfo
				db.First(&userInfo, &UserInfo{Name: name})
				if userInfo.Name == name {
					ginLog("[ManagerAction]", "del Normal user "+name)
					db.Delete(&userInfo)
					var portPwd = make(map[string]string)
					portPwd[userInfo.Port] = userInfo.Password
					e := HandleConfigJson(ConfigJsonPath, portPwd, false)
					if e != nil {
						c.IndentedJSON(http.StatusOK, gin.H{"code": "0", "msg": e.Error()})
						return
					}

					c.IndentedJSON(http.StatusOK, gin.H{"code": "1", "msg": ssrRestart()})
					return
				}
				c.IndentedJSON(http.StatusOK, gin.H{"status": "not exist"})
				return

			} else {
				c.IndentedJSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
			}
		})

		//登录获取配置
		v1.GET("/login/:token/:name", func(c *gin.Context) {
			token := c.Param("token")
			name := c.Param("name")
			var userInfo UserInfo
			db.First(&userInfo, &UserInfo{Token: token, Name: name})
			if userInfo.Name == name && userInfo.Type == UserTypeSu {
				//管理员
				var users []UserInfo
				db.Find(&users)
				configs := make([]ShadowsocksConfig, 0)
				for _, v := range users {
					var config ShadowsocksConfig
					config.CreateTime = v.CreateTime
					config.UpdateTime = v.UpdateTime
					config.Remarks = v.Name
					config.Server = c.Request.Host
					config.ServerPort = v.Port
					config.Password = v.Password
					config.Method = SsrMethod
					config.Protocol = SsrProtocol
					config.Obfs = SsrObfs
					config.SubscriptionUrl = "http://" + c.Request.Host + "/v1/login/" + v.Token + "/" + v.Name
					configs = append(configs, config)
				}

				c.IndentedJSON(http.StatusOK, configs)

			} else if userInfo.Name == name && userInfo.Type == UserTypeNormal {
				//普通用户
				var config ShadowsocksConfig
				config.CreateTime = userInfo.CreateTime
				config.UpdateTime = userInfo.UpdateTime
				config.Remarks = userInfo.Name
				config.Server = c.Request.Host
				config.ServerPort = userInfo.Port
				config.Password = userInfo.Password
				config.Method = SsrMethod
				config.SubscriptionUrl = "http://" + c.Request.Host + "/v1/login/" + userInfo.Token + "/" + userInfo.Name
				config.Protocol = SsrProtocol
				config.Obfs = SsrObfs
				c.IndentedJSON(http.StatusOK, config)

			} else {
				c.IndentedJSON(http.StatusOK, gin.H{"status": "404"})
			}
		})

		v1.GET("/ssr/restart/:token", func(c *gin.Context) {
			token := c.Param("token")
			var userInfo UserInfo
			db.First(&userInfo, &UserInfo{Token: token})
			if userInfo.Name != "" && userInfo.Type == UserTypeSu {
				c.String(http.StatusOK, ssrRestart())
			} else {
				c.IndentedJSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
			}
		})
	}

}

//初始化数据库
func initDb() {
	db, err = gorm.Open("sqlite3", "./ssr.db")
	if err != nil {
		panic("initDb error " + err.Error())
	}

	db.AutoMigrate(&UserInfo{})
	hasModel := db.HasTable(&UserInfo{})
	if hasModel {
		ginLog("[initDb]", "检查模型`UserInfo`表是否存在(Yes)")
	}
	hasTable := db.HasTable("user_infos")
	if hasTable {
		ginLog("[initDb]", "检查表`user_infos`表是否存在(Yes)")
	} else {
		// 为模型`UserInfo`创建表
		db.CreateTable(&UserInfo{})
	}

	//创建root用户
	var suUserInfo UserInfo
	db.First(&suUserInfo)
	if suUserInfo.ID == 0 {
		pwd := pwgen.AlphaNum(10)
		suUserInfo := CreateUser(RootName, pwd, UserTypeSu)
		var portPwd = make(map[string]string)
		portPwd[suUserInfo.Port] = pwd
		e := HandleConfigJson(ConfigJsonPath, portPwd, true)
		if e != nil {
			ginLog("[initDb]", "create Manager user err "+e.Error())
			return
		}
	}
	ginLog("[initDb]", " Manager user token="+suUserInfo.Token)

}

//创建新用户
func CreateUser(name string, pwd string, userType uint) UserInfo {
	var port = makeRangeNum(20000, 65000)
	for configExistPort(port) {
		port = makeRangeNum(20000, 65000)
	}
	info := UserInfo{Name: name, Password: pwd, Token: makeMd5Token(), Port: str(port),
		Type: userType, CreateTime: str(makeTimestamp()), UpdateTime: str(makeTimestamp())}
	db.Create(&info)
	return info
}

func configExistPort(port int) bool {
	data, err := ioutil.ReadFile(ConfigJsonPath)
	if err != nil {
		return false
	}
	jsonText := string(data)
	portPassword := gjson.Get(jsonText, "port_password")
	results := portPassword.Map()
	_, exist := results[string(port)]
	return exist
}

//重启shadowsocks服务
func ssrRestart() string {
	cmd := exec.Command(CmdSsrRestart, "restart")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "shadowsocks restart failed with " + err.Error() + "\n"
	}
	ginLog("[shadowsocks]", " restart")
	return string(out) + "\n"
}

//处理配置文件
func HandleConfigJson(jsonFile string, ppwd map[string]string, isAdd bool) error {
	// Read json buffer from jsonFile
	byteValue, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return err
	}

	// We have known the outer json object is a map, so we define  result as map.
	// otherwise, result could be defined as slice if outer is an array
	var result map[string]interface{}
	err = json.Unmarshal(byteValue, &result)
	if err != nil {
		return err
	}

	// handle peers
	portPasswords := result["port_password"].(map[string]interface{})

	for k, v := range ppwd {
		if isAdd {
			portPasswords[k] = v
		} else {
			delete(portPasswords, k)
		}
	}

	// Convert golang object back to byte
	byteValue, err = json.MarshalIndent(result, "", "    ")
	if err != nil {
		return err
	}

	// Write back to file
	err = ioutil.WriteFile(jsonFile, byteValue, 0644)
	return err
}

func ginLog(tag string, content string) {
	gin.DefaultWriter.Write([]byte(tag + " " + formatAsDate() + " | " + content + "\n"))
}
