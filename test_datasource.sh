#!/bin/bash

# 数据源测试脚本
echo "=== PromAI 数据源测试 ==="
echo "测试时间: $(date)"
echo

SERVER_URL="http://localhost:8091"
DEFAULT_DATASOURCE="http://prometheus.k8s.monitoring.kubehan.cn"
CUSTOM_DATASOURCE="http://test-prometheus.example.com:9090"

echo "1. 测试无 datasource 参数（应该使用默认数据源）"
echo "请求: $SERVER_URL/api/promai/getreport"
curl -s "$SERVER_URL/api/promai/getreport" > test1_report.html 2>/dev/null
if [ -f "test1_report.html" ]; then
    echo "✅ 报告生成成功"
    if grep -q "数据源:" test1_report.html; then
        DATASOURCE1=$(grep "数据源:" test1_report.html | sed 's/.*数据源: *//' | head -1)
        echo "📋 使用的数据源: $DATASOURCE1"
    else
        echo "❌ 报告中未找到数据源信息"
    fi
else
    echo "❌ 报告生成失败"
fi
echo

echo "2. 测试传入自定义 datasource 参数"
echo "请求: $SERVER_URL/api/promai/getreport?datasource=$CUSTOM_DATASOURCE"
curl -s "$SERVER_URL/api/promai/getreport?datasource=$CUSTOM_DATASOURCE" > test2_report.html 2>/dev/null
if [ -f "test2_report.html" ]; then
    echo "✅ 报告生成成功"
    if grep -q "数据源:" test2_report.html; then
        DATASOURCE2=$(grep "数据源:" test2_report.html | sed 's/.*数据源: *//' | head -1)
        echo "📋 使用的数据源: $DATASOURCE2"
    else
        echo "❌ 报告中未找到数据源信息"
    fi
else
    echo "❌ 报告生成失败"
fi
echo

echo "3. 数据源对比分析"
if [ -f "test1_report.html" ] && [ -f "test2_report.html" ]; then
    echo "🔍 对比两个报告的数据源..."

    DATASOURCE1=$(grep "数据源:" test1_report.html 2>/dev/null | sed 's/.*数据源: *//' | head -1)
    DATASOURCE2=$(grep "数据源:" test2_report.html 2>/dev/null | sed 's/.*数据源: *//' | head -1)

    if [ "$DATASOURCE1" != "$DATASOURCE2" ]; then
        echo "✅ 数据源不同，说明自定义数据源生效了:"
        echo "   默认数据源: $DATASOURCE1"
        echo "   自定义数据源: $DATASOURCE2"
    else
        echo "❌ 数据源相同，说明自定义数据源未生效:"
        echo "   两个报告都使用: $DATASOURCE1"
    fi
else
    echo "❌ 无法对比，缺少报告文件"
fi
echo

echo "4. 服务器日志分析"
echo "请查看服务器日志中的以下调试信息:"
echo "   - [DEBUG] 使用的Prometheus URL: ..."
echo "   - [DEBUG] 创建自定义Prometheus客户端，URL: ..."
echo "   - [DEBUG] 自定义collector创建完成，数据源: ..."
echo "   - [DEBUG] 开始收集指标，使用数据源: ..."
echo "   - [DEBUG] 查询指标 ..., 查询语句: ..., 数据源: ..."
echo

# 清理测试文件
rm -f test1_report.html test2_report.html
echo "测试完成"