//go:build windows

package gozero

func init() {
	PythonDefaultOptions.Engine = "python.exe"
}
