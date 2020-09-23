package main

import (
  "flag"
  "github.com/emicklei/go-restful"
  "net/http"
  "os"

  "k8s.io/apimachinery/pkg/util/wait"
  "k8s.io/component-base/logs"
  "k8s.io/klog"

  basecmd "github.com/kubernetes-incubator/custom-metrics-apiserver/pkg/cmd"
  "github.com/kubernetes-incubator/custom-metrics-apiserver/pkg/provider"
)
type haAdapter struct {
  basecmd.AdapterBase

  // Message is printed on succesful startup
  Message string
}

func (a *haAdapter) makeProviderOrDie() (provider.MetricsProvider, *restful.WebService) {
  client, err := a.DynamicClient()
  if err != nil {
    klog.Fatalf("unable to construct dynamic client: %v", err)
  }

  mapper, err := a.RESTMapper()
  if err != nil {
    klog.Fatalf("unable to construct discovery REST mapper: %v", err)
  }

  return NewProvider(client, mapper)
}

func main() {
  logs.InitLogs()
  defer logs.FlushLogs()

  cmd := &haAdapter{}
  cmd.Flags().StringVar(&cmd.Message, "msg", "starting adapter...", "startup message")
  cmd.Flags().AddGoFlagSet(flag.CommandLine) // make sure we get the klog flags
  cmd.Flags().Parse(os.Args)

  testProvider, webService := cmd.makeProviderOrDie()
  cmd.WithCustomMetrics(testProvider)
  cmd.WithExternalMetrics(testProvider)

  klog.Infof(cmd.Message)
  
  restful.DefaultContainer.Add(webService)
  go func() {
    klog.Fatal(http.ListenAndServe(":8080", nil))
  }()
  if err := cmd.Run(wait.NeverStop); err != nil {
    klog.Fatalf("unable to run custom metrics adapter: %v", err)
  }
}
