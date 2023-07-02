package main

import (
	"fmt"
	"net"
	"regexp"

	"github.com/miekg/dns"
)

const (
	ActionForward = "forward"
	ActionRefused = "refused"
	ActionFailed  = "failed"
)

type CompiledRuleSet struct {
	Domains map[string]Domain
}

type Domain struct {
	Name    string
	Ruleset []Rule
}

type Ruleset struct {
}

/*
func NewCompiledRuleSet(config *Config) (*CompiledRuleSet, error) {
	rs := CompiledRuleSet{}
	if err := rs.ParseConfig(config); err != nil {
		return nil, err
	}
	return &rs, nil
}
*/

func (c *CompiledRuleSet) ParseConfig(config *Config) error {
	domains := map[string]Domain{}
	errs := []error{}
	for domain, rulelist := range config.Rules {
		domain = dns.Fqdn(domain)
		rules := []Rule{}
		for _, rule := range rulelist {
			if r, err := newRule(rule); err == nil {
				rules = append(rules, *r)
			} else {
				errs = append(errs, err)
			}
		}
		domains[domain] = Domain{Name: domain, Ruleset: rules}
	}
	c.Domains = domains
	if len(errs) > 0 {
		return fmt.Errorf("errors parsing config: %s", errs)
	}
	return nil
}

func newRule(rc RuleConfig) (*Rule, error) {
	errs := []error{}
	rule := Rule{Name: rc.Name, Description: rc.Description}
	for i, pattern := range rc.Match.Patterns {
		if p, err := regexp.Compile(pattern); err == nil {
			rule.Match.Patterns = append(rule.Match.Patterns, *p)
		} else {
			sugar.Warnf("pattern:%v fail to parse pattern: %s: %s", i, pattern, err)
			errs = append(errs, err)
		}
	}

	for i, iprange := range rc.Match.SourceIps {
		if _, p, err := net.ParseCIDR(iprange); err == nil {
			rule.Match.SourceIps = append(rule.Match.SourceIps, *p)
		} else {
			sugar.Warnf("range:%v fail to parse range: %s: %s", i, iprange, err)
			errs = append(errs, err)
		}
	}

	for i, qt := range rc.Match.QueryTypes {
		if value, found := txt2dnstype[qt]; found {
			rule.Match.QueryTypes = append(rule.Match.QueryTypes, value)
		} else {
			sugar.Warnf("query type:%v fail to find query type %s", i, qt)
			errs = append(errs, fmt.Errorf("fail to find query type %s", qt))
		}
	}

	for i, iprange := range rc.Match.AnsweredAddress.NotIn {
		if _, p, err := net.ParseCIDR(iprange); err == nil {
			rule.Match.AnsweredAddress.NotIn = append(rule.Match.AnsweredAddress.NotIn, *p)
		} else {
			sugar.Warnf("AnsweredAddress.NotIn range:%v fail to parse range: %s: %s", i, iprange, err)
			errs = append(errs, err)
		}
	}

	switch rc.Then.Action {
	case ActionForward, ActionRefused, ActionFailed:
		rule.Then.Action = rc.Then.Action
	default:
		sugar.Warnf("action type unknown: %s", rc.Then.Action)
		errs = append(errs, fmt.Errorf("action type unknown: %s", rc.Then.Action))
	}

	for _, tgt := range rc.Then.Targets {
		if host, _, err := net.SplitHostPort(tgt); err != nil {
			sugar.Warnf("unable to parse target %s", tgt)
			errs = append(errs, fmt.Errorf("unable to parse target %s", tgt))
		} else if parsed := net.ParseIP(host); parsed == nil {
			sugar.Warnf("unable to parse target %s", tgt)
			errs = append(errs, fmt.Errorf("unable to parse target %s", tgt))
		} else {
			rule.Then.Targets = append(rule.Then.Targets, tgt)
		}
	}

	if rule.Then.Action == "forward" && len(rule.Then.Targets) == 0 {
		errs = append(errs, fmt.Errorf("then has forward action but no target"))
	}

	if len(errs) != 0 {
		return nil, fmt.Errorf("multiple errors while parsing rule: %s", errs)
	}

	return &rule, nil
}

type Rule struct {
	Name        string
	Description string
	Match       Match
	Then        Then
}

type Match struct {
	SourceIps       []net.IPNet
	Patterns        []regexp.Regexp
	QueryTypes      []uint16
	AnsweredAddress AnsweredAddress
}

type AnsweredAddress struct {
	NotIn []net.IPNet
}

type Then struct {
	Action  string
	Targets []string
}

func (r *Rule) MatchQuestion(question dns.Question, sanitized_name string, remoteAddr net.Addr) *Then {
	var match bool
	// query types against question.Qtype
	if len(r.Match.QueryTypes) > 0 {
		match = false
		for _, qt := range r.Match.QueryTypes {
			if qt == question.Qtype {
				match = true
				break
			}
		}
		if !match {
			return nil
		}
	}

	// remote addr against remoteAddr
	if len(r.Match.SourceIps) > 0 {
		match = false
		remoteip, _, _ := net.SplitHostPort(remoteAddr.String())
		for _, valid_range := range r.Match.SourceIps {
			if valid_range.Contains(net.IP(remoteip)) {
				match = true
				break
			}
		}
		if !match {
			return nil
		}
	}

	// patterns against question.Name
	if len(r.Match.Patterns) > 0 {
		match = false
		for _, pattern := range r.Match.Patterns {
			if pattern.MatchString(sanitized_name) {
				match = true
				break
			}
		}
		if !match {
			return nil
		}
	}

	return &r.Then
}

func (r *Rule) CheckResponse() bool {
	return true
}
