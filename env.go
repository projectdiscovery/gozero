package gozero

import "fmt"

type Variable struct {
	Name  string
	Value string
}

func (v *Variable) String() string {
	return fmt.Sprintf("%s=%s", v.Name, v.Value)
}

func extendWithVars(env []string, vars ...Variable) []string {
	for _, v := range vars {
		env = append(env, v.String())
	}
	return env
}
