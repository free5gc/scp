package logger

import (
	logger_util "github.com/free5gc/util/logger"
	"github.com/sirupsen/logrus"
)

var (
	Log         *logrus.Logger
	NfLog       *logrus.Entry
	MainLog     *logrus.Entry
	InitLog     *logrus.Entry
	CfgLog      *logrus.Entry
	CmiLog      *logrus.Entry
	CtxLog      *logrus.Entry
	GinLog      *logrus.Entry
	SBILog      *logrus.Entry
	ConsumerLog *logrus.Entry
	DetectorLog *logrus.Entry
	ProxyLog    *logrus.Entry
	MNSLog      *logrus.Entry // MNS
)

func init() {
	fieldsOrder := []string{
		logger_util.FieldNF,
		logger_util.FieldCategory,
	}
	Log = logger_util.New(fieldsOrder)
	NfLog = Log.WithField(logger_util.FieldNF, "SCP")
	MainLog = NfLog.WithField(logger_util.FieldCategory, "Main")
	InitLog = NfLog.WithField(logger_util.FieldCategory, "Init")
	CfgLog = NfLog.WithField(logger_util.FieldCategory, "CFG")
	CtxLog = NfLog.WithField(logger_util.FieldCategory, "CTX")
	CmiLog = NfLog.WithField(logger_util.FieldCategory, "CMI")
	GinLog = NfLog.WithField(logger_util.FieldCategory, "GIN")
	SBILog = NfLog.WithField(logger_util.FieldCategory, "SBI")
	ConsumerLog = NfLog.WithField(logger_util.FieldCategory, "Consumer")
	DetectorLog = NfLog.WithField(logger_util.FieldCategory, "Detector")
	ProxyLog = NfLog.WithField(logger_util.FieldCategory, "Proxy")
	MNSLog = NfLog.WithField(logger_util.FieldCategory, "MNS") // MNS
}
