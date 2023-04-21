package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

var (
	levels = map[string]string{
		"DEF":     "\033[00;38;5;240m",
		"FAIL":    "\033[48;5;160;38;5;230m",
		"SUCCESS": "\033[01;38;5;64m",
		"WARN":    "\033[00;38;5;136m",
		"INFO":    "\033[01;38;5;33m",
		"CLEAR":   "\033[0m",
	}
)

type (
	Service struct {
		*log.Logger
	}
)

func New(prefix string, flags int) *Service {
	if flags == 0 {
		flags = log.Lmsgprefix
	}

	return &Service{
		Logger: log.New(os.Stdout, fmt.Sprintf("%s::", prefix), flags),
	}
}

func (l *Service) Print(level, msg string, args ...interface{}) {
	lev, ok := levels[level]
	if !ok {
		lev = "DEF"
	}

	os.Stdout.WriteString(fmt.Sprintf("%s %s %s %s %s\n",
		time.Now().Format("Mon, 2 Jan 2006 15:04:05 MST"),
		lev,
		l.Logger.Prefix(),
		levels["CLEAR"],
		fmt.Sprintf(msg, args...),
	))
}
