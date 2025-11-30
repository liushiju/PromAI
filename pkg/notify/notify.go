package notify

import (
	"bytes"
	"context"
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

	"PromAI/pkg/report"
	"PromAI/pkg/utils"

	"github.com/jordan-wright/email"
)

type DingtalkConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Webhook   string `yaml:"webhook"`
	Secret    string `yaml:"secret"`
	ReportURL string `yaml:"report_url"`
}

type EmailConfig struct {
	Enabled   bool     `yaml:"enabled"`
	SMTPHost  string   `yaml:"smtp_host"`
	SMTPPort  int      `yaml:"smtp_port"`
	Username  string   `yaml:"username"`
	Password  string   `yaml:"password"`
	From      string   `yaml:"from"`
	To        []string `yaml:"to"`
	ReportURL string   `yaml:"report_url"`
}

type WeChatWorkConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Webhook   string `yaml:"webhook"`
	ProxyURL  string `yaml:"proxy_url"`
	ReportURL string `yaml:"report_url"`
}

type AlertSummary struct {
	TotalAlerts    int
	CriticalAlerts int
	WarningAlerts  int
	NormalMetrics  int
	TotalMetrics   int
}

type TypeAlertSummary struct {
	Type          string
	TotalMetrics  int
	CriticalCount int
	WarningCount  int
	NormalCount   int
}

// calculateAlertSummary 从报告数据中计算告警汇总
func CalculateAlertSummary(data report.ReportData) AlertSummary {
	summary := AlertSummary{}

	for _, group := range data.MetricGroups {
		for _, metrics := range group.MetricsByName {
			for _, metric := range metrics {
				summary.TotalMetrics++

				switch metric.Status {
				case "critical":
					summary.CriticalAlerts++
					summary.TotalAlerts++
				case "warning":
					summary.WarningAlerts++
					summary.TotalAlerts++
				default:
					summary.NormalMetrics++
				}
			}
		}
	}

	return summary
}

// CalculateTypeAlertSummary 按照metric_types.type分类计算告警汇总
func CalculateTypeAlertSummary(data report.ReportData) []TypeAlertSummary {
	typeSummaries := make(map[string]*TypeAlertSummary)

	for typeName, group := range data.MetricGroups {
		summary := &TypeAlertSummary{
			Type: typeName,
		}

		for _, metrics := range group.MetricsByName {
			for _, metric := range metrics {
				summary.TotalMetrics++

				switch metric.Status {
				case "critical":
					summary.CriticalCount++
				case "warning":
					summary.WarningCount++
				default:
					summary.NormalCount++
				}
			}
		}

		typeSummaries[typeName] = summary
	}

	// 转换为切片并按照类型名称排序
	result := make([]TypeAlertSummary, 0, len(typeSummaries))
	for _, summary := range typeSummaries {
		result = append(result, *summary)
	}

	// 按照类型名称排序
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Type > result[j].Type {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// config/config.yaml 中 dingtalk 配置
// notifications:
//   dingtalk:
//     enabled: true
//     webhook: "https://oapi.dingtalk.com/robot/send?access_token=29f727c8c973e5fb8d8339968d059393a4b4bb0bdcd667d592996035a8c0e135"
//     secret: "SEC75fd20834b42064b86c1aa97930738befeb2fe214044649397752212c5894848"

// SendDingtalk 发送钉钉通知（兼容版本）
func SendDingtalk(config DingtalkConfig, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
	return SendDingtalkWithContext(context.Background(), config, reportPath, projectName, Datasource, alertSummary)
}

// SendDingtalkWithContext 发送钉钉通知（支持动态URL）
func SendDingtalkWithContext(ctx context.Context, config DingtalkConfig, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
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

	// 生成报告的访问链接
	reportFileName := filepath.Base(reportPath)

	// 尝试从context中获取HTTP请求对象，用于动态URL生成
	var reportLink string
	if r, ok := ctx.Value("http_request").(*http.Request); ok {
		// 打印调试信息
		log.Printf("调试信息: r.Host = %s", r.Host)
		log.Printf("调试信息: X-Forwarded-Host = %s", r.Header.Get("X-Forwarded-Host"))
		log.Printf("调试信息: X-Forwarded-Proto = %s", r.Header.Get("X-Forwarded-Proto"))
		log.Printf("调试信息: TLS = %v", r.TLS != nil)

		// 使用动态URL生成
		reportLink = utils.GetReportURL(r, reportFileName)
		log.Printf("使用动态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	} else {
		// 回退到配置的静态URL
		reportLink = fmt.Sprintf("%s/api/promai/reports/%s", config.ReportURL, reportFileName)
		log.Printf("使用配置的静态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	}
	fmt.Printf("报告链接: %s", reportLink)

	// 添加消息内容
	alertStatus := "✅ 正常"
	if alertSummary.TotalAlerts > 0 {
		alertStatus = "⚠️ 异常"
	}

	messageContent := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": "巡检报告",
			"text": fmt.Sprintf("## 🔍 %s 巡检报告已生成 %s\n\n"+
				"### ⏰ 生成时间\n"+
				"> %s\n\n"+
				"### 🚨 告警汇总\n"+
				"**总体状态**：%s\n"+
				"**总指标数**：%d\n"+
				"**异常指标**：%d\n"+
				"  🔴 严重告警：%d\n"+
				"  🟡 警告告警：%d\n"+
				"**正常指标**：%d\n\n"+
				"### 📄 报告详情\n"+
				"**文件名**：`%s`\n"+
				"**访问链接**：[点击查看报告](%s)\n\n"+
				"---\n"+
				"💡 请登录环境查看完整报告内容",
				projectName,
				alertStatus,
				time.Now().Format("2006-01-02 15:04:05"),
				alertStatus,
				alertSummary.TotalMetrics,
				alertSummary.TotalAlerts,
				alertSummary.CriticalAlerts,
				alertSummary.WarningAlerts,
				alertSummary.NormalMetrics,
				reportFileName,
				reportLink),
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

// SendEmail 发送邮件通知（兼容版本）
func SendEmail(config EmailConfig, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
	return SendEmailWithContext(context.Background(), config, reportPath, projectName, Datasource, alertSummary)
}

// SendEmailWithContext 发送邮件通知（支持动态URL）
func SendEmailWithContext(ctx context.Context, config EmailConfig, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
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

	// 生成报告的访问链接
	reportFileName := filepath.Base(reportPath)

	// 尝试从context中获取HTTP请求对象，用于动态URL生成
	var reportLink string
	if r, ok := ctx.Value("http_request").(*http.Request); ok {
		// 打印调试信息
		log.Printf("调试信息: r.Host = %s", r.Host)
		log.Printf("调试信息: X-Forwarded-Host = %s", r.Header.Get("X-Forwarded-Host"))
		log.Printf("调试信息: X-Forwarded-Proto = %s", r.Header.Get("X-Forwarded-Proto"))
		log.Printf("调试信息: TLS = %v", r.TLS != nil)

		// 使用动态URL生成
		reportLink = utils.GetReportURL(r, reportFileName)
		log.Printf("使用动态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	} else {
		// 回退到配置的静态URL
		reportLink = fmt.Sprintf("%s/api/promai/reports/%s", config.ReportURL, reportFileName)
		log.Printf("使用配置的静态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	}

	// 添加更丰富的邮件内容
	alertStatus := "✅ 正常"
	statusColor := "#28a745"
	if alertSummary.TotalAlerts > 0 {
		alertStatus = "⚠️ 异常"
		statusColor = "#ffc107"
	}
	if alertSummary.CriticalAlerts > 0 {
		statusColor = "#dc3545"
	}

	e.HTML = []byte(fmt.Sprintf(`
        <h2 style="color: %s;">🔍 %s 巡检报告已生成 %s</h2>
        
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <h3 style="color: #495057; margin-top: 0;">🚨 告警汇总</h3>
            <table style="border-collapse: collapse; width: 100%%;">
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6;"><strong>总体状态：</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: %s;">%s</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6;"><strong>总指标数：</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6;">%d</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6;"><strong>异常指标：</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: #dc3545;">%d</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; padding-left: 20px;"><strong>🔴 严重告警：</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: #dc3545;">%d</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; padding-left: 20px;"><strong>🟡 警告告警：</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: #ffc107;">%d</td>
                </tr>
                <tr>
                    <td style="padding: 8px;"><strong>正常指标：</strong></td>
                    <td style="padding: 8px; color: #28a745;">%d</td>
                </tr>
            </table>
        </div>
        
        <div style="background-color: #e9ecef; padding: 15px; border-radius: 5px;">
            <h3 style="color: #495057; margin-top: 0;">📄 报告详情</h3>
            <p><strong>生成时间：</strong>%s</p>
            <p><strong>报告文件：</strong>%s</p>
            <p><strong>在线查看：</strong><a href="%s" style="color: #007bff;">点击查看报告</a></p>
        </div>
        
        <p style="margin-top: 20px; color: #6c757d;"><strong>请登录环境查看完整报告内容!</strong></p>
    `,
		statusColor,
		projectName,
		alertStatus,
		statusColor,
		alertStatus,
		alertSummary.TotalMetrics,
		alertSummary.TotalAlerts,
		alertSummary.CriticalAlerts,
		alertSummary.WarningAlerts,
		alertSummary.NormalMetrics,
		time.Now().Format("2006-01-02 15:04:05"),
		reportFileName,
		reportLink))

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

// SendWeChatWork 发送企业微信通知（兼容版本）
func SendWeChatWork(config WeChatWorkConfig, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
	return SendWeChatWorkWithContext(context.Background(), config, reportPath, projectName, Datasource, alertSummary)
}

// SendWeChatWorkWithWebhook 发送企业微信通知（支持动态机器人key）
func SendWeChatWorkWithWebhook(ctx context.Context, botKey string, proxyURL string, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
	if botKey == "" {
		log.Printf("企业微信机器人key为空")
		return nil
	}

	// 构建完整的webhook URL
	webhookURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=%s", botKey)
	log.Printf("开始发送企业微信通知，使用机器人key: %s", botKey)

	// 尝试从context中获取报告数据，用于分类汇总
	var typeSummaries []TypeAlertSummary
	if data, ok := ctx.Value("report_data").(report.ReportData); ok {
		typeSummaries = CalculateTypeAlertSummary(data)
		log.Printf("从报告数据中计算出分类汇总")
	} else {
		log.Printf("未找到报告数据，使用空分类汇总")
		typeSummaries = []TypeAlertSummary{}
	}

	// 生成报告的访问链接
	reportFileName := filepath.Base(reportPath)

	// 尝试从context中获取HTTP请求对象，用于动态URL生成
	var reportLink string
	if r, ok := ctx.Value("http_request").(*http.Request); ok {
		// 打印调试信息
		log.Printf("调试信息: r.Host = %s", r.Host)
		log.Printf("调试信息: X-Forwarded-Host = %s", r.Header.Get("X-Forwarded-Host"))
		log.Printf("调试信息: X-Forwarded-Proto = %s", r.Header.Get("X-Forwarded-Proto"))
		log.Printf("调试信息: TLS = %v", r.TLS != nil)

		// 使用动态URL生成
		reportLink = utils.GetReportURL(r, reportFileName)
		log.Printf("使用动态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	} else {
		// 回退到配置的静态URL（如果传入的webhookURL中包含配置信息）
		reportLink = fmt.Sprintf("%s/api/promai/reports/%s", "https://alert.intra.kubehan.cn", reportFileName)
		log.Printf("使用默认静态URL生成报告链接: %s", reportLink)
	}

	// 构建消息内容
	alertStatus := "✅ 正常"
	if alertSummary.TotalAlerts > 0 {
		alertStatus = "⚠️ 异常"
	}

	// 构建分类汇总部分
	typeSummaryText := ""
	for _, summary := range typeSummaries {
		typeStatus := "✅"
		if summary.CriticalCount > 0 {
			typeStatus = "❌"
		} else if summary.WarningCount > 0 {
			typeStatus = "⚠️"
		}
		typeSummaryText += fmt.Sprintf("**%s%s**：总%d个，异常%d个（严重%d，警告%d），正常%d个\n",
			typeStatus, summary.Type, summary.TotalMetrics,
			summary.CriticalCount+summary.WarningCount, summary.CriticalCount, summary.WarningCount, summary.NormalCount)
	}

	messageContent := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]interface{}{
			"content": fmt.Sprintf("【监测报告】`%s`巡检结果 %s\n\n"+
				"### ⏰ 巡检时间\n"+
				"%s\n\n"+
				"### 📊 分类巡检结果\n"+
				"%s\n"+
				"### 📈 整体统计\n"+
				"**总指标数**：%d个\n"+
				"**异常指标**：%d个（严重%d个，警告%d个）\n"+
				"**正常指标**：%d个\n\n"+
				"📋[点击查看完整报告](%s)\n\n"+
				"⏰ 生成时间：%s",
				Datasource,
				alertStatus,
				time.Now().Format("2006-01-02 15:04:05"),
				typeSummaryText,
				alertSummary.TotalMetrics,
				alertSummary.TotalAlerts,
				alertSummary.CriticalAlerts,
				alertSummary.WarningAlerts,
				alertSummary.NormalMetrics,
				reportLink,
				time.Now().Format("2006-01-02 15:04:05")),
		},
	}

	jsonData, err := json.Marshal(messageContent)
	if err != nil {
		log.Printf("JSON编码失败: %v", err)
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	// 创建HTTP客户端
	client := &http.Client{}

	// 如果配置了代理，设置代理
	if proxyURL != "" {
		log.Printf("使用代理服务器: %s", proxyURL)
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			log.Printf("解析代理URL失败: %v", err)
			return fmt.Errorf("解析代理URL失败: %v", err)
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
		}
		client.Transport = transport
	}

	// 发送请求
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	log.Printf("准备发送请求到 webhook: %s", webhookURL)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("发送请求失败: %v", err)
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("企业微信响应状态码: %d, 响应内容: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("企业微信发送失败，状态码: %d", resp.StatusCode)
	}

	log.Printf("企业微信通知发送成功")
	return nil
}

// SendWeChatWorkWithContext 发送企业微信通知（支持动态URL）
func SendWeChatWorkWithContext(ctx context.Context, config WeChatWorkConfig, reportPath string, projectName string, Datasource string, alertSummary AlertSummary) error {
	if !config.Enabled {
		log.Printf("企业微信通知未启用")
		return nil
	}
	log.Printf("开始发送企业微信通知...")

	// 尝试从context中获取报告数据，用于分类汇总
	var typeSummaries []TypeAlertSummary
	if data, ok := ctx.Value("report_data").(report.ReportData); ok {
		typeSummaries = CalculateTypeAlertSummary(data)
		log.Printf("从报告数据中计算出分类汇总")
	} else {
		log.Printf("未找到报告数据，使用空分类汇总")
		typeSummaries = []TypeAlertSummary{}
	}

	// 生成报告的访问链接
	reportFileName := filepath.Base(reportPath)

	// 尝试从context中获取HTTP请求对象，用于动态URL生成
	var reportLink string
	if r, ok := ctx.Value("http_request").(*http.Request); ok {
		// 打印调试信息
		log.Printf("调试信息: r.Host = %s", r.Host)
		log.Printf("调试信息: X-Forwarded-Host = %s", r.Header.Get("X-Forwarded-Host"))
		log.Printf("调试信息: X-Forwarded-Proto = %s", r.Header.Get("X-Forwarded-Proto"))
		log.Printf("调试信息: TLS = %v", r.TLS != nil)

		// 使用动态URL生成
		reportLink = utils.GetReportURL(r, reportFileName)
		log.Printf("使用动态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	} else {
		// 回退到配置的静态URL
		reportLink = fmt.Sprintf("%s/api/promai/reports/%s", config.ReportURL, reportFileName)
		log.Printf("使用配置的静态URL生成报告链接: %s", reportLink)
		log.Printf("最终生成的 reportLink = %s", reportLink)
	}

	// 构建消息内容
	alertStatus := "✅ 正常"
	if alertSummary.TotalAlerts > 0 {
		alertStatus = "⚠️ 异常"
	}

	// 构建分类汇总部分
	typeSummaryText := ""
	for _, summary := range typeSummaries {
		typeStatus := "✅"
		if summary.CriticalCount > 0 {
			typeStatus = "❌"
		} else if summary.WarningCount > 0 {
			typeStatus = "⚠️"
		}
		typeSummaryText += fmt.Sprintf("**%s%s**：总%d个，异常%d个（严重%d，警告%d），正常%d个\n",
			typeStatus, summary.Type, summary.TotalMetrics,
			summary.CriticalCount+summary.WarningCount, summary.CriticalCount, summary.WarningCount, summary.NormalCount)
	}

	messageContent := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]interface{}{
			"content": fmt.Sprintf("【监测报告】`%s`巡检结果 %s\n\n"+
				"### ⏰ 巡检时间\n"+
				"%s\n\n"+
				"### 📊 分类巡检结果\n"+
				"%s\n"+
				"### 📈 整体统计\n"+
				"**总指标数**：%d个\n"+
				"**异常指标**：%d个（严重%d个，警告%d个）\n"+
				"**正常指标**：%d个\n\n"+
				"📋[点击查看完整报告](%s)\n\n"+
				"⏰ 生成时间：%s",
				Datasource,
				alertStatus,
				time.Now().Format("2006-01-02 15:04:05"),
				typeSummaryText,
				alertSummary.TotalMetrics,
				alertSummary.TotalAlerts,
				alertSummary.CriticalAlerts,
				alertSummary.WarningAlerts,
				alertSummary.NormalMetrics,
				reportLink,
				time.Now().Format("2006-01-02 15:04:05")),
		},
	}

	jsonData, err := json.Marshal(messageContent)
	if err != nil {
		log.Printf("JSON编码失败: %v", err)
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	// 创建HTTP客户端
	client := &http.Client{}

	// 如果配置了代理，设置代理
	if config.ProxyURL != "" {
		log.Printf("使用代理服务器: %s", config.ProxyURL)
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			log.Printf("解析代理URL失败: %v", err)
			return fmt.Errorf("解析代理URL失败: %v", err)
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		client.Transport = transport
	}

	// 发送请求
	req, err := http.NewRequest("POST", config.Webhook, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	log.Printf("准备发送请求到 webhook: %s", config.Webhook)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("发送请求失败: %v", err)
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("企业微信响应状态码: %d, 响应内容: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("企业微信发送失败，状态码: %d", resp.StatusCode)
	}

	log.Printf("企业微信通知发送成功")
	return nil
}
