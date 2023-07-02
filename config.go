package main

import (
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	configFilename  string
	configFileMtime time.Time
	Listen          map[string]Binding
	Rules           map[string][]RuleConfig `yaml:"rules"`
}

type Binding struct {
	Address string
	Port    int
}

type RuleConfig struct {
	Name        string
	Description string
	Match       MatchConfig
	Then        ThenConfig
}

type Network struct {
	Network net.IPNet
}

func (n *Network) UnmarshalText(text []byte) error {
	_, network, err := net.ParseCIDR(string(text))
	n.Network = *network
	return err
}

type MatchConfig struct {
	QueryTypes      []string `yaml:"query types"`
	Patterns        []string
	SourceIps       []string              `yaml:"source ips"`
	AnsweredAddress AnsweredAddressConfig `yaml:"answered address"`
}

type AnsweredAddressConfig struct {
	NotIn []string `yaml:"not in"`
	// In    []string `yaml:"in"`
}

type ThenConfig struct {
	Action  string
	Targets []string
}

func (c *Config) Load(configfile string) error {
	data, err := os.ReadFile(configfile)
	if err != nil {
		panic(err)
	}
	c.configFilename = configfile
	fi, _ := os.Stat(c.configFilename)
	c.configFileMtime = fi.ModTime()

	return c.parse(data)
}

func (c *Config) Reload() (bool, error) {
	fi, err := os.Stat(c.configFilename)
	if err != nil {
		return false, err
	}
	if c.configFileMtime == fi.ModTime() {
		return false, nil
	}

	if err := c.Load(c.configFilename); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Config) parse(configdata []byte) error {
	err := yaml.Unmarshal(configdata, &c)
	return err
}

func (c *Config) CompileToRuleset() (*CompiledRuleSet, error) {
	rs := CompiledRuleSet{}
	if err := rs.ParseConfig(c); err != nil {
		return nil, err
	}
	return &rs, nil
}
