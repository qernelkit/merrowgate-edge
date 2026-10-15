// edgectl is the control API of the Merrowgate depot gateway.
//
//	edgectl [serve]           run the API, the telemetry relay and enrolment
//	edgectl selfcheck         load the settings and keys, report problems, exit
//	edgectl import-v1 FILE    import admin accounts from a v1 appliance export
//	edgectl audit-check       verify the audit log chain
//	edgectl version           print the version and module list
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"merrowgate.example/edge/internal/admin"
	"merrowgate.example/edge/internal/api"
	"merrowgate.example/edge/internal/audit"
	"merrowgate.example/edge/internal/config"
	"merrowgate.example/edge/internal/enrol"
	"merrowgate.example/edge/internal/firmware"
	"merrowgate.example/edge/internal/mqtt"
	"merrowgate.example/edge/internal/server"
	"merrowgate.example/edge/internal/session"
	"merrowgate.example/edge/internal/sshca"
	"merrowgate.example/edge/internal/tokens"
	"merrowgate.example/edge/internal/webhook"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	configPath := flag.String("config", config.DefaultPath, "gateway settings file")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: edgectl [-config FILE] [serve|selfcheck|import-v1 FILE|audit-check|version]")
	}
	flag.Parse()

	cmd := flag.Arg(0)
	if cmd == "" {
		cmd = "serve"
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(*configPath)
	case "selfcheck":
		err = selfcheck(*configPath)
	case "import-v1":
		err = importV1(*configPath, flag.Arg(1))
	case "audit-check":
		err = auditCheck(*configPath)
	case "version":
		printVersion()
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("edgectl %s: %v", cmd, err)
	}
}

func serve(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		return err
	}
	master, err := masterSecret(cfg.StatePath("master.secret"))
	if err != nil {
		return err
	}

	issuer, err := tokens.NewIssuer(cfg)
	if err != nil {
		return err
	}
	hasher, err := admin.NewHasher(cfg.Admin)
	if err != nil {
		return err
	}
	accounts, err := admin.OpenStore(cfg.StatePath("accounts.sealed"), master)
	if err != nil {
		return err
	}
	if accounts.Len() == 0 {
		log.Printf("no admin accounts yet: run `edgectl import-v1` or create one with the provisioning tool")
	}
	verifier, err := firmware.LoadVerifier(cfg.PKIPath(firmware.KeyFile))
	if err != nil {
		return err
	}
	authority, err := sshca.LoadOrCreate(cfg.StatePath("engineer-authority"), cfg.Engineers.CertTTL)
	if err != nil {
		return err
	}
	auditLog, err := audit.Open(cfg.StatePath("audit.log"))
	if err != nil {
		return err
	}
	defer auditLog.Close()

	sender, err := webhookSender(cfg.Webhooks)
	if err != nil {
		return err
	}
	cloud, err := server.NewUpstream(cfg.Upstream.URL, cfg.Upstream.Timeout, cfg.Depot.GatewayID)
	if err != nil {
		return err
	}
	relayPassword, err := readSecret(cfg.Telemetry.PasswordFile)
	if err != nil {
		return err
	}
	relay, err := mqtt.NewRelay(cfg.Depot.Site, cfg.Depot.GatewayID, cfg.Telemetry, string(relayPassword), cloud)
	if err != nil {
		return err
	}
	keyring, err := session.NewKeyring()
	if err != nil {
		return err
	}

	handlers, err := api.New(api.Deps{
		Config:   cfg,
		Issuer:   issuer,
		Hasher:   hasher,
		Accounts: accounts,
		Keyring:  keyring,
		Relay:    relay,
		Firmware: verifier,
		SSHCA:    authority,
		Audit:    auditLog,
		Webhooks: sender,
	})
	if err != nil {
		return err
	}
	srv, err := server.New(cfg.Listen.API, cfg.PKIPath(server.ListenerCertFile), cfg.PKIPath(server.ListenerKeyFile), handlers.Handler())
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go relay.Run(ctx.Done())
	go keyring.RotateDaily(ctx.Done(), log.Printf)

	enroller := enrol.New(cfg.StateDir, cfg.Depot.GatewayID, cfg.Depot.Site, cloud)
	if !enroller.Enrolled() {
		if err := enroller.Prepare(); err != nil {
			return err
		}
		go enroller.Wait(ctx, 10*time.Minute)
	}
	return srv.Run(ctx)
}

// masterSecret reads the gateway's master secret, creating it on first start. It
// protects the sealed files in state_dir and is never copied off the gateway.
func masterSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: want 32 bytes, found %d", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	log.Printf("created %s", path)
	return b, nil
}

// webhookSender returns the event sender, or one that sends nothing until the
// operators' shared secret is provisioned.
func webhookSender(cfg config.Webhooks) (*webhook.Sender, error) {
	secret, err := readSecret(cfg.SecretFile)
	if errors.Is(err, fs.ErrNotExist) {
		log.Printf("webhooks off: %s is not provisioned", cfg.SecretFile)
		return webhook.Off(), webhook.CheckConfig(cfg)
	}
	if err != nil {
		return nil, err
	}
	return webhook.NewSender(cfg, secret)
}

func readSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

func selfcheck(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	var problems []error
	if _, err := tokens.NewIssuer(cfg); err != nil {
		problems = append(problems, err)
	}
	if _, err := admin.NewHasher(cfg.Admin); err != nil {
		problems = append(problems, err)
	}
	if _, err := firmware.LoadVerifier(cfg.PKIPath(firmware.KeyFile)); err != nil {
		problems = append(problems, err)
	}
	if err := webhook.CheckConfig(cfg.Webhooks); err != nil {
		problems = append(problems, err)
	}
	if _, err := mqtt.NewRelay(cfg.Depot.Site, cfg.Depot.GatewayID, cfg.Telemetry, "", nil); err != nil {
		problems = append(problems, err)
	}
	if err := errors.Join(problems...); err != nil {
		return err
	}
	fmt.Println("selfcheck: ok")
	return nil
}

func importV1(configPath, file string) error {
	if file == "" {
		return errors.New("usage: edgectl import-v1 FILE (the export password is read from stdin)")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	export, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "export password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("reading export password: %w", err)
	}
	accounts, err := admin.ImportV1(export, strings.TrimRight(line, "\r\n"))
	if err != nil {
		return err
	}
	master, err := masterSecret(cfg.StatePath("master.secret"))
	if err != nil {
		return err
	}
	store, err := admin.OpenStore(cfg.StatePath("accounts.sealed"), master)
	if err != nil {
		return err
	}
	if err := store.Put(accounts...); err != nil {
		return err
	}
	fmt.Printf("imported %d accounts; each is rehashed at its first sign-in\n", len(accounts))
	return nil
}

func auditCheck(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	f, err := os.Open(cfg.StatePath("audit.log"))
	if err != nil {
		return err
	}
	defer f.Close()
	seq, _, err := audit.Check(f)
	if err != nil {
		return err
	}
	fmt.Printf("audit log intact: %d records\n", seq)
	return nil
}

func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Println("edgectl (no build info)")
		return
	}
	fmt.Printf("edgectl %s (%s)\n", info.Main.Version, info.GoVersion)
	for _, d := range info.Deps {
		fmt.Printf("  %s %s\n", d.Path, d.Version)
	}
}
