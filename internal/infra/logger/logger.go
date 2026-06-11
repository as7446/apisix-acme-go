package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Log 全局日志实例
var Log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	AddSource: true,
	Level:     slog.LevelInfo,
}))

// Init 根据配置初始化日志级别
func Init(level string) {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	Log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     l,
	}))
}