package main

import (
	"log/slog"
	"os"
)

// Log 为全局日志实例
var Log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	AddSource: true,
	Level:     slog.LevelInfo,
}))
