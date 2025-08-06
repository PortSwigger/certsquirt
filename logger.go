package main

import (
	"log/slog"
	"os"
)

var (
	logger      *slog.Logger
	auditLogger *slog.Logger
)

// LogConfig holds logging configuration
type LogConfig struct {
	Level      string // "DEBUG", "INFO", "WARN", "ERROR"
	Format     string // "json" or "text"
	AuditFile  string // path to audit log file, empty for stdout
}

// InitLogging initializes the structured logger based on configuration
func InitLogging(cfg LogConfig, debug bool) {
	var level slog.Level
	switch cfg.Level {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		if debug {
			level = slog.LevelDebug
		} else {
			level = slog.LevelInfo
		}
	}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
			AddSource: true,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
			AddSource: true,
		})
	}

	logger = slog.New(handler)
	slog.SetDefault(logger)

	// Set up audit logger
	var auditHandler slog.Handler
	var auditOutput *os.File = os.Stdout
	
	if cfg.AuditFile != "" {
		var err error
		auditOutput, err = os.OpenFile(cfg.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logger.Error("Failed to open audit log file, using stdout", "error", err, "file", cfg.AuditFile)
			auditOutput = os.Stdout
		}
	}

	auditHandler = slog.NewJSONHandler(auditOutput, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		AddSource: true,
	})
	auditLogger = slog.New(auditHandler)
}

// GetLogger returns the main application logger
func GetLogger() *slog.Logger {
	if logger == nil {
		// Fallback initialization with default settings
		InitLogging(LogConfig{Level: "INFO", Format: "text"}, false)
	}
	return logger
}

// GetAuditLogger returns the audit logger for security events
func GetAuditLogger() *slog.Logger {
	if auditLogger == nil {
		// Fallback initialization 
		InitLogging(LogConfig{Level: "INFO", Format: "text"}, false)
	}
	return auditLogger
}

// AuditEvent logs a security audit event with consistent structure
func AuditEvent(operation string, success bool, details ...any) {
	auditLogger.Info("AUDIT",
		append([]any{
			"operation", operation,
			"success", success,
			"timestamp", "auto", // slog adds timestamp automatically
		}, details...)...)
}