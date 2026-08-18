// Command authentik-operator watches Ingress and HTTPRoute objects across the
// cluster for authentik.gddnet.io/* annotations and reconciles the
// corresponding Authentik Applications/Providers.
package main

import (
	"os"
	"strconv"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/negativefeedback/authentik-operator/internal/authentik"
	"github.com/negativefeedback/authentik-operator/internal/controller"
)

var (
	scheme  = runtime.NewScheme()
	version = "dev"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(envBool("DEBUG", false))))
	logger := ctrl.Log.WithName("setup")
	logger.Info("authentik-operator starting", "version", version)

	authentikURL := requireEnv(logger, "AUTHENTIK_URL")
	authentikToken := requireEnv(logger, "AUTHENTIK_TOKEN")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: envString("METRICS_BIND_ADDRESS", ":8080"),
		},
		HealthProbeBindAddress: envString("HEALTH_PROBE_BIND_ADDRESS", ":8081"),
		LeaderElection:         envBool("LEADER_ELECT", false),
		LeaderElectionID:       "authentik-operator.gddnet.io",
	})
	if err != nil {
		logger.Error(err, "unable to start manager")
		os.Exit(1)
	}

	shared := &controller.Shared{
		Client:    mgr.GetClient(),
		Authentik: authentik.New(authentikURL, authentikToken),
		Gateway: controller.GatewayRef{
			Name:        envString("GATEWAY_NAME", "external"),
			Namespace:   envString("GATEWAY_NAMESPACE", "kube-system"),
			SectionName: envString("GATEWAY_SECTION_NAME", "https"),
		},
		AuthentikNamespace:   envString("AUTHENTIK_NAMESPACE", "gdd-security"),
		AuthentikServiceName: envString("AUTHENTIK_SERVICE_NAME", "authentik-server"),
		AuthentikServicePort: int32(envInt("AUTHENTIK_SERVICE_PORT", 80)),
	}

	if err := (&controller.IngressReconciler{Shared: shared}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to set up Ingress controller")
		os.Exit(1)
	}
	if err := (&controller.HTTPRouteReconciler{Shared: shared}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to set up HTTPRoute controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	logger.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func requireEnv(logger interface{ Error(error, string, ...any) }, key string) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error(nil, "missing required environment variable", "key", key)
		os.Exit(1)
	}
	return v
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
