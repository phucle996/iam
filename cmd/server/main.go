package main

import (
	"controlplane/pkg/logger"
	"os"
	"os/signal"
	"syscall"
	"time"

	"controlplane/internal/app"
	"controlplane/internal/config"
)

func main() {
	// 1. load config
	cfg := config.LoadConfig()

	// 2. apply process-wide settings
	loc, err := time.LoadLocation(cfg.App.TimeZone)

	if err != nil {
		logger.SysWarn("main", "Failed to load timezone from environment variable "+cfg.App.TimeZone+": "+err.Error())
		time.Local = time.UTC
	} else {
		time.Local = loc
	}
	// initialize custom logger
	logger.InitLogger()

	// 3. create application
	application, err := app.NewApplication(cfg)
	if err != nil {
		logger.SysFatal("main", "Failed to initialize application: "+err.Error())
	}

	// 4. prepare for signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// 5. start
	go func() {
		if err := application.Start(cfg); err != nil {
			logger.SysError("main", "Application failed to start: "+err.Error())
			stop <- syscall.SIGTERM
		}
	}()

	// 6. wait for signal
	<-stop

	// 7. trigger graceful shutdown
	application.Stop()
	logger.SysInfo("main", "Application stopped gracefully.")
}
