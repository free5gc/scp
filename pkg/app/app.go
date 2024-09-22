package app

import (
	"context"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"

	scp_context "github.com/free5gc/scp/internal/context"
	"github.com/free5gc/scp/internal/logger"
	"github.com/free5gc/scp/internal/sbi"
	"github.com/free5gc/scp/internal/sbi/consumer"
	"github.com/free5gc/scp/internal/sbi/processor"
	"github.com/free5gc/scp/pkg/factory"
	"github.com/sirupsen/logrus"
)

type ScpApp struct {
	ctx context.Context
	wg  sync.WaitGroup
	cfg *factory.Config

	scpCtx    *scp_context.ScpContext
	consumer  *consumer.Consumer
	proc      *processor.Processor
	sbiServer *sbi.Server
}

func NewApp(cfg *factory.Config, tlsKeyLogPath string) (*ScpApp, error) {
	var err error
	scp := &ScpApp{cfg: cfg}
	scp.SetLogEnable(cfg.GetLogEnable())
	scp.SetLogLevel(cfg.GetLogLevel())
	scp.SetReportCaller(cfg.GetLogReportCaller())

	if scp.scpCtx, err = scp_context.NewContext(scp); err != nil {
		return nil, err
	}
	if scp.consumer, err = consumer.NewConsumer(scp); err != nil {
		return nil, err
	}
	if scp.proc, err = processor.NewProcessor(scp); err != nil {
		return nil, err
	}
	if scp.sbiServer, err = sbi.NewServer(scp, tlsKeyLogPath); err != nil {
		return nil, err
	}
	return scp, nil
}

func (a *ScpApp) Config() *factory.Config {
	return a.cfg
}

func (a *ScpApp) Context() *scp_context.ScpContext {
	return a.scpCtx
}

func (a *ScpApp) Consumer() *consumer.Consumer {
	return a.consumer
}

func (a *ScpApp) Processor() *processor.Processor {
	return a.proc
}

func (a *ScpApp) SbiServer() *sbi.Server {
	return a.sbiServer
}

func (a *ScpApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == ioutil.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(ioutil.Discard)
	}
}

func (a *ScpApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *ScpApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *ScpApp) Run() error {
	var cancel context.CancelFunc
	a.ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	a.wg.Add(1)
	/* Go Routine is spawned here for listening for cancellation event on
	 * context */
	go a.listenShutdownEvent()

	if err := a.sbiServer.Run(&a.wg); err != nil {
		return err
	}

	if err := a.consumer.RegisterNFInstance(); err != nil {
		return err
	}

	// Wait for interrupt signal to gracefully shutdown UPF
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	// Receive the interrupt signal
	logger.MainLog.Infof("Shutdown SCP ...")
	// Notify each goroutine and wait them stopped
	cancel()
	a.WaitRoutineStopped()
	logger.MainLog.Infof("SCP exited")
	return nil
}

func (a *ScpApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		a.wg.Done()
	}()

	<-a.ctx.Done()
	a.sbiServer.Stop()
}

func (a *ScpApp) WaitRoutineStopped() {
	a.wg.Wait()
	a.Terminate()
}

func (a *ScpApp) Start() {
	if err := a.Run(); err != nil {
		logger.MainLog.Errorf("SCP Run err: %v", err)
	}
}

func (a *ScpApp) Terminate() {
	logger.MainLog.Infof("Terminating SCP...")

	// deregister with NRF
	if err := a.consumer.DeregisterNFInstance(); err != nil {
		logger.MainLog.Error(err)
	} else {
		logger.MainLog.Infof("Deregister from NRF successfully")
	}
	logger.MainLog.Infof("SCP terminated")
}
