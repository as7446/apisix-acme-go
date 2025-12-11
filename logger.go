package main

import (
	"log"
	"os"
)

// Log 为全局日志实例
var Log = log.New(os.Stdout, "[apisix-acme-go] ", log.LstdFlags|log.Lshortfile)
