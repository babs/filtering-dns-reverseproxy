package main

import (
	"flag"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger
var sugar *zap.SugaredLogger

var crs *CompiledRuleSet
var config *Config

type cli struct {
	config_filename  *string
	devLog           *bool
	noColorLog       *bool
	enableStackTrace *bool
}

func main() {
	rand.Seed(time.Now().Unix())
	cli := new(cli)
	cli.config_filename = flag.String("config", "config.yaml", "config file")
	cli.devLog = flag.Bool("dev", false, "dev log else prod log (json format)")
	cli.noColorLog = flag.Bool("no-color", false, "color log")
	cli.enableStackTrace = flag.Bool("enableStackTrace", false, "don't disable stacktrace")
	flag.Parse()

	initLog(cli)
	defer logger.Sync() // flushes buffer, if any
	sugar = logger.Sugar()

	config = new(Config)
	err := config.Load(*cli.config_filename)
	if err != nil {
		log.Fatalf("error in base config %v", err)
	}

	crs, err = config.CompileToRuleset()
	if err != nil {
		log.Fatalf("error in base config %v", err)
	}

	if len(config.Listen) == 0 {
		log.Fatalf("no listen defined")
	}

	dns.HandleFunc(".", handleRequest)

	servers := make(map[string]*dns.Server)

	for netproto, binding := range config.Listen {
		go func(netproto string, binding Binding) {
			server := &dns.Server{
				Addr: binding.Address + ":" + strconv.Itoa(binding.Port),
				Net:  netproto,
			}
			sugar.Infof("starting on %s:%s", netproto, binding.Address+":"+strconv.Itoa(binding.Port))
			err := server.ListenAndServe()
			defer server.Shutdown()
			servers[netproto+":"+binding.Address+":"+strconv.Itoa(binding.Port)] = server
			if err != nil {
				sugar.Fatalf("failed to serv: %s", err.Error())
			}
		}(netproto, binding)
	}

	initConfAutoReload(cli)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	for _, server := range servers {
		server.Shutdown()
	}
}

func handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	remoteaddr := w.RemoteAddr()
	if len(req.Question) != 1 {
		sugar.Infow(
			"more than one question in request",
			"req", req,
		)
		dns.HandleFailed(w, req)
		return
	}
	the_question := req.Question[0]
	canonicalized_name := dns.Fqdn(strings.ToLower(the_question.Name))
	qtypetxt := dnstype2txt[the_question.Qtype]
	sugar.Debugw(
		"incomming request",
		"qname", the_question.Name,
		"canonicalized_name", canonicalized_name,
		"qtype", qtypetxt,
		"qclass", the_question.Qclass,
		"remote", remoteaddr,
	)

	var domainrulesetname string
	var domaindef Domain
	matchlen := 0
	for domain, ruleset := range crs.Domains {
		if strings.HasSuffix(canonicalized_name, domain) {
			clen := len(domain)
			if clen > matchlen {
				matchlen = clen
				domainrulesetname = domain
				domaindef = ruleset
			}
		}
	}

	if matchlen == 0 {
		sugar.Warnw("no domain found to handle query", "domain", canonicalized_name)
		dns.HandleFailed(w, req)
		return
	} else {
		sugar.Debugw(
			"selected domain ruleset",
			"domainrulesetname", domainrulesetname,
			"canonicalized_name", canonicalized_name,
			"qtype", qtypetxt,
		)
	}

	var fate *Then
	var matchingrule Rule
	var rulenum int
	for rulenum, rule := range domaindef.Ruleset {
		if fate = rule.MatchQuestion(the_question, canonicalized_name, remoteaddr); fate != nil {
			matchingrule = rule
			sugar.Debugw(
				"rule match",
				"domainrulesetname", domainrulesetname,
				"rulenum", rulenum,
				"rulename", rule.Name,
				"canonicalized_name", canonicalized_name,
				"qtype", qtypetxt,
			)
			break
		}
	}

	if fate == nil || fate.Action == ActionRefused {
		sugar.Infow(
			"answer deliberately refused",
			"domainrulesetname", domainrulesetname,
			"rulenum", rulenum,
			"query", the_question,
			"from", remoteaddr,
		)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	if fate.Action == ActionFailed {
		sugar.Infow(
			"answer deliberately servfail",
			"domainrulesetname", domainrulesetname,
			"rulenum", rulenum,
			"query", the_question,
			"from", remoteaddr,
		)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	if fate.Action == ActionForward {
		c := &dns.Client{Net: "udp"}
		target := fate.Targets[rand.Intn(len(fate.Targets))]
		resp, _, err := c.Exchange(req, target)
		if err != nil {
			sugar.Warnw(
				"error while forwarding request",
				"domainrulesetname", domainrulesetname,
				"rulenum", rulenum,
				"err", err,
				"query", the_question,
				"target", target,
				"from", remoteaddr,
			)
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		// filter out goes here!
		if !matchingrule.CheckResponse(resp) {
			sugar.Infow(
				"answer forward converted to refused due to response payload filtering",
				"domainrulesetname", domainrulesetname,
				"rulenum", rulenum,
				"query", the_question,
				"target", target,
				"from", remoteaddr,
				"resp", resp,
			)
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}
		sugar.Infow(
			"answer forward",
			"domainrulesetname", domainrulesetname,
			"rulenum", rulenum,
			"query", the_question,
			"target", target,
			"from", remoteaddr,
			"resp", resp,
		)

		w.WriteMsg(resp)
	}

}

func initLog(cli *cli) {
	var zapconfig zap.Config
	if *cli.devLog {
		zapconfig = zap.NewDevelopmentConfig()
		if !*cli.noColorLog {
			color.NoColor = false
			zapconfig.EncoderConfig.EncodeLevel = func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
				colfunc := func(s string, _ ...interface{}) string { return s }
				switch l {
				case zap.DebugLevel:
					colfunc = color.BlueString
				case zap.InfoLevel:
					colfunc = color.GreenString
					// colfunc = color.New(color.FgHiGreen, color.Bold).SprintfFunc()
				case zapcore.WarnLevel:
					colfunc = color.New(color.FgHiYellow, color.Bold).SprintfFunc()
				case zapcore.ErrorLevel | zapcore.DPanicLevel | zapcore.PanicLevel | zapcore.FatalLevel:
					colfunc = color.New(color.FgRed, color.Bold).SprintfFunc()
				}
				enc.AppendString(colfunc(l.CapitalString()))
			}
		}
	} else {
		zapconfig = zap.NewProductionConfig()
	}

	if !*cli.enableStackTrace {
		zapconfig.DisableStacktrace = true
	}
	logger, _ = zapconfig.Build()
}

func initConfAutoReload(cli *cli) {
	reload_conf_chan := make(chan os.Signal, 1)
	signal.Notify(reload_conf_chan, syscall.SIGHUP)
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for {
			select {
			case <-reload_conf_chan:
				sugar.Debugw("reload config by signal")
			case <-ticker.C:
				sugar.Debugw("reload config by timer")
			}
			changed, err := config.Reload()
			if !changed {
				sugar.Debugw("no change in config file, skip")
			}
			if err != nil {
				sugar.Debugw("error in config file, skip")
			}

			tempcrs, err := config.CompileToRuleset()
			if err != nil {
				sugar.Warnf("error in base config %v", err)
			} else {
				crs = tempcrs
			}
		}
	}()
}
