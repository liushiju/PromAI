package notify

import (
	"PromAI/pkg/utils"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jordan-wright/email"
)

type DingtalkConfig struct {
	Enabled bool   `yaml:"enabled"`
	Webhook string `yaml:"webhook"`
	Secret  string `yaml:"secret"`
}

type EmailConfig struct {
	Enabled  bool     `yaml:"enabled"`
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

// config/config.yaml 中 dingtalk 配置
// notifications:
//   dingtalk:
//     enabled: true
//     webhook: "https://oapi.dingtalk.com/robot/send?access_token=29f727c8c973e5fb8d8339968d059393a4b4bb0bdcd667d592996035a8c0e135"
//     secret: "SEC75fd20834b42064b86c1aa97930738befeb2fe214044649397752212c5894848"

// SendDingtalk 发送钉钉通知
func SendDingtalk(config DingtalkConfig, reportPath string) error {
	if !config.Enabled {
		log.Printf("钉钉通知未启用")
		return nil
	}
	log.Printf("开始发送钉钉通知...")
	// 计算时间戳和签名
	timestamp := time.Now().UnixMilli()
	sign := calculateDingtalkSign(timestamp, config.Secret)
	webhook := fmt.Sprintf("%s&timestamp=%d&sign=%s", config.Webhook, timestamp, sign)

	log.Printf("准备发送请求到 webhook: %s", webhook)
	// 创建multipart表单
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 添加文件
	file, err := os.Open(reportPath)
	if err != nil {
		log.Printf("打开文件失败: %v", err)
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile("file", filepath.Base(reportPath))
	if err != nil {
		log.Printf("创建表单文件失败: %v", err)
		return fmt.Errorf("创建表单文件失败: %v", err)
	}

	fileContent, err := os.ReadFile(reportPath)
	if err != nil {
		log.Printf("读取文件失败: %v", err)
		return fmt.Errorf("读取文件失败: %v", err)
	}
	part.Write(fileContent)

	port := utils.GetGlobalPort()
	ip := utils.GetLocalIPs()[0]
	// 添加消息内容
	messageContent := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": "巡检报告",
			"text": fmt.Sprintf("## 🔍 巡检报告已生成\n\n"+
				"### ⏰ 生成时间\n"+
				"> %s\n\n"+
				"### 📄 报告详情\n"+
				"- **文件名**：`%s`\n"+
				"- **访问链接**：[点击查看报告](http://%s:%s/reports/%s)\n\n"+
				"---\n"+
				"💡 请登录环境查看完整报告内容",
				time.Now().Format("2006-01-02 15:04:05"),
				filepath.Base(reportPath),
				ip,
				port,
				filepath.Base(reportPath)),
		},
	}

	jsonData, err := json.Marshal(messageContent)
	if err != nil {
		log.Printf("JSON编码失败: %v", err)
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	// 发送请求
	req, err := http.NewRequest("POST", webhook, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("发送请求失败: %v", err)
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("钉钉响应状态码: %d, 响应内容: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("钉钉发送失败，状态码: %d", resp.StatusCode)
	}

	log.Printf("钉钉通知发送成功")
	return nil
}

// SendEmail 发送邮件通知
func SendEmail(config EmailConfig, reportPath string) error {
	if !config.Enabled {
		log.Printf("邮件通知未启用")
		return nil
	}

	log.Printf("开始发送邮件通知...")
	log.Printf("SMTP服务器: %s:%d", config.SMTPHost, config.SMTPPort)
	log.Printf("发件人: %s", config.From)
	log.Printf("收件人: %v", config.To)

	e := email.NewEmail()
	e.From = config.From
	e.To = config.To
	e.Subject = "巡检报告"

	// 设置邮件正文
	port := utils.GetGlobalPort()
	ip := utils.GetLocalIPs()[0]

	// 添加更丰富的邮件内容
	e.HTML = []byte(fmt.Sprintf(`
        <h2>🔍 巡检报告已生成</h2>
        <p><strong>生成时间：</strong>%s</p>
        <p><strong>报告文件：</strong>%s</p>
        <p><strong>在线查看：</strong><a href="http://%s:%s/reports/%s">点击查看报告</a></p>
        <p><strong>请登录环境查看完整报告内容!</strong></p>
    `,
		time.Now().Format("2006-01-02 15:04:05"),
		filepath.Base(reportPath),
		ip,
		port,
		filepath.Base(reportPath),
	))

	// 添加附件
	if _, err := e.AttachFile(reportPath); err != nil {
		log.Printf("添加附件失败: %v", err)
		return fmt.Errorf("添加附件失败: %v", err)
	}

	// 发送邮件（使用TLS）
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         config.SMTPHost,
	}

	log.Printf("正在发送邮件...")
	if err := e.SendWithTLS(addr, auth, tlsConfig); err != nil {
		log.Printf("发送邮件失败: %v", err)
		log.Printf("SMTP配置信息:")
		log.Printf("- 服务器: %s", config.SMTPHost)
		log.Printf("- 端口: %d", config.SMTPPort)
		log.Printf("- 用户名: %s", config.Username)
		return fmt.Errorf("发送邮件失败: %v", err)
	}

	log.Printf("邮件发送成功")
	return nil
}

// calculateDingtalkSign 计算钉钉签名
func calculateDingtalkSign(timestamp int64, secret string) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
}
