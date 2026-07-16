package daemon

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
)

const launchdLabel = "com.generalized-labs.ironrun"

var ErrUnsupported = errors.New("the persistent Ironrun daemon is not supported on this platform")

func UnitPreview() (path, content string, err error) {
	executable, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	switch runtime.GOOS {
	case "darwin":
		path = filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
		content = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>daemon</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
`, launchdLabel, html.EscapeString(executable))
	case "linux":
		config, configErr := os.UserConfigDir()
		if configErr != nil {
			return "", "", configErr
		}
		path = filepath.Join(config, "systemd", "user", "ironrun.service")
		content = fmt.Sprintf(`[Unit]
Description=Ironrun value-blind local coordination service

[Service]
ExecStart=%s daemon run
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=default.target
`, strconv.Quote(executable))
	default:
		return "", "", ErrUnsupported
	}
	return path, content, nil
}

func Install() (string, error) {
	path, content, err := UnitPreview()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", err
	}
	if err := Start(); err != nil {
		return path, err
	}
	return path, nil
}

func Start() error {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		path := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
		domain := fmt.Sprintf("gui/%d", currentUID())
		_ = exec.Command("launchctl", "bootout", domain+"/"+launchdLabel).Run()
		if out, err := exec.Command("launchctl", "bootstrap", domain, path).CombinedOutput(); err != nil {
			return fmt.Errorf("start launchd service: %s", safeServiceOutput(out))
		}
		return nil
	case "linux":
		if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("reload systemd user units: %s", safeServiceOutput(out))
		}
		if out, err := exec.Command("systemctl", "--user", "enable", "--now", "ironrun.service").CombinedOutput(); err != nil {
			return fmt.Errorf("start systemd user service: %s", safeServiceOutput(out))
		}
		return nil
	default:
		return ErrUnsupported
	}
}

func Stop() error {
	switch runtime.GOOS {
	case "darwin":
		domain := fmt.Sprintf("gui/%d/%s", currentUID(), launchdLabel)
		if out, err := exec.Command("launchctl", "bootout", domain).CombinedOutput(); err != nil {
			return fmt.Errorf("stop launchd service: %s", safeServiceOutput(out))
		}
		return nil
	case "linux":
		if out, err := exec.Command("systemctl", "--user", "disable", "--now", "ironrun.service").CombinedOutput(); err != nil {
			return fmt.Errorf("stop systemd user service: %s", safeServiceOutput(out))
		}
		return nil
	default:
		return ErrUnsupported
	}
}

func Uninstall() error {
	path, _, err := UnitPreview()
	if err != nil {
		return err
	}
	_ = Stop()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if runtime.GOOS == "linux" {
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	}
	return nil
}

func safeServiceOutput(out []byte) string {
	if len(out) == 0 {
		return "command failed"
	}
	if len(out) > 300 {
		out = out[:300]
	}
	return string(out)
}
