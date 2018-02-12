// config.go -- YAML config file parsing
//
// Author: Sudhi Herle <sudhi@herle.net>
// License: GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main


import (
	"fmt"
	"io/ioutil"
	"net"

	yaml "gopkg.in/yaml.v2"
)

// List of config entries
type Conf struct {
	Logging  string `yaml:"log"`
	LogLevel string `yaml:"loglevel"`
	URLlog   string `yaml:"urllog"`
	Http     []ListenConf
	Socks    []ListenConf
}

type ListenConf struct {
	Listen netaddr  `yaml:"listen"`
	Bind   netaddr  `yaml:"bind"`
	Allow  []subnet `yaml:"allow"`
	Deny   []subnet `yaml:"deny"`

	// Global and Per-Host rate limit
	Ratelimit RateLimit `yaml:"ratelimit"`
}

type RateLimit struct {
	Global  int `yaml:"global"`
	PerHost int `yaml:"perhost"`
}

// An IP/Subnet
type subnet struct {
	*net.IPNet
}

type netaddr struct {
        *net.TCPAddr
}

// custom unmarshaler for TCP Addr
func (n *netaddr) UnmarshalYAML(unm func(v interface{}) error) error {
	var s string

	// First unpack the bytes as a string. We then parse the string
	// as a CIDR
	err := unm(&s)
	if err != nil {
		return err
	}

        a, err := net.ResolveTCPAddr("tcp", s)
        if err == nil {
                n.TCPAddr = a
        }
        return err
}

// Custom unmarshaler for IPNet
func (ipn *subnet) UnmarshalYAML(unm func(v interface{}) error) error {
	var s string

	// First unpack the bytes as a string. We then parse the string
	// as a CIDR
	err := unm(&s)
	if err != nil {
		return err
	}

	_, net, err := net.ParseCIDR(s)
	if err == nil {
                ipn.IPNet = net
	}
	return err
}

// Parse config file in YAML format and return
func ReadYAML(fn string) (*Conf, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("Can't read config file %s: %s", fn, err)
	}

	var cfg Conf
	err = yaml.Unmarshal(yml, &cfg)
	if err != nil {
		return nil, fmt.Errorf("Can't parse config file %s: %s", fn, err)
	}

	return &cfg, nil
}

// vim: ft=go:sw=8:ts=8:expandtab:tw=88:
