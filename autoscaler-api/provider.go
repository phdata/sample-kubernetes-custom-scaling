package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/emicklei/go-restful"
	"github.com/kubernetes-incubator/custom-metrics-apiserver/pkg/provider"
	"github.com/kubernetes-incubator/custom-metrics-apiserver/pkg/provider/helpers"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog"
	"k8s.io/metrics/pkg/apis/custom_metrics"
	"k8s.io/metrics/pkg/apis/external_metrics"
)

type replicaMetrics struct {
	Replicas int `json:"replicas"`
}

type CustomMetricResource struct {
	provider.CustomMetricInfo
	types.NamespacedName
}

// externalMetric provides examples for metrics which would otherwise be reported from an external source
type externalMetric struct {
	info   provider.ExternalMetricInfo
	labels map[string]string
	value  external_metrics.ExternalMetricValue
}

var (
	testingExternalMetrics = []externalMetric{}
)

const Replicas = "replicas"

type metricValue struct {
	labels labels.Set
	value  resource.Quantity
}

// exampleProvider is a sample implementation of provider.MetricsProvider which stores a map of fake metrics
type exampleProvider struct {
	client dynamic.Interface
	mapper apimeta.RESTMapper

	valuesLock      sync.RWMutex
	values          map[CustomMetricResource]metricValue //todo custom
	externalMetrics []externalMetric
}

// NewProvider returns an instance of haProvider, along with its restful.WebService that opens endpoints to post new fake metrics
func NewProvider(client dynamic.Interface, mapper apimeta.RESTMapper) (provider.MetricsProvider, *restful.WebService) {
	provider := &exampleProvider{
		client:          client,
		mapper:          mapper,
		values:          make(map[CustomMetricResource]metricValue),
		externalMetrics: testingExternalMetrics,
	}
	return provider, provider.webService()
}

// webService creates a restful.WebService with routes set up for receiving fake metrics
// These writing routes have been set up to be identical to the format of routes which metrics are read from.
// There are 3 metric types available: namespaced, root-scoped, and namespaces.
// (Note: Namespaces, we're assuming, are themselves namespaced resources, but for consistency with how metrics are retreived they have a separate route)
func (p *exampleProvider) webService() *restful.WebService {
	ws := new(restful.WebService)

	ws.Path("/write-metrics")

	// Namespaced resources
	ws.Route(ws.POST("/namespaces/{namespace}/{resourceType}/{name}/{metric}").To(p.updateMetric).
		Param(ws.BodyParameter("value", "value to set metric").DataType("integer").DefaultValue("0")))

	// Root-scoped resources
	ws.Route(ws.POST("/{resourceType}/{name}/{metric}").To(p.updateMetric).
		Param(ws.BodyParameter("value", "value to set metric").DataType("integer").DefaultValue("0")))

	// Namespaces, where {resourceType} == "namespaces" to match API
	ws.Route(ws.POST("/{resourceType}/{name}/metrics/{metric}").To(p.updateMetric).
		Param(ws.BodyParameter("value", "value to set metric").DataType("integer").DefaultValue("0")))
	return ws
}

// updateMetric writes the metric provided by a restful request and stores it in memory
func (p *exampleProvider) updateMetric(request *restful.Request, response *restful.Response) {
	p.valuesLock.Lock()
	defer p.valuesLock.Unlock()

	namespace := request.PathParameter("namespace")
	resourceType := request.PathParameter("resourceType")
	namespaced := false
	if len(namespace) > 0 || resourceType == "namespaces" {
		namespaced = true
	}
	name := request.PathParameter("name")
	metricName := request.PathParameter("metric")

	value := new(resource.Quantity)
	err := request.ReadEntity(value)
	if err != nil {
		response.WriteErrorString(http.StatusBadRequest, err.Error())
		return
	}

	groupResource := schema.ParseGroupResource(resourceType)

	metricLabels := labels.Set{}
	sel := request.QueryParameter("labels")
	if len(sel) > 0 {
		metricLabels, err = labels.ConvertSelectorToLabelsMap(sel)
		if err != nil {
			response.WriteErrorString(http.StatusBadRequest, err.Error())
			return
		}
	}

	info := provider.CustomMetricInfo{
		GroupResource: groupResource,
		Metric:        metricName,
		Namespaced:    namespaced,
	}

	info, _, err = info.Normalized(p.mapper)
	if err != nil {
		klog.Errorf("Error normalizing info: %s", err)
	}
	namespacedName := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}

	metricInfo := CustomMetricResource{
		CustomMetricInfo: info,
		NamespacedName:   namespacedName,
	}

	value.Set(int64(0))

	if info.Metric == Replicas {
		value.Set(int64(getReplicas(name)))
	}

	p.values[metricInfo] = metricValue{
		labels: metricLabels,
		value:  *value,
	}
}

// valueFor is a helper function to get just the value of a specific metric
func (p *exampleProvider) valueFor(info provider.CustomMetricInfo, name types.NamespacedName, metricSelector labels.Selector) (resource.Quantity, error) {
	info, _, err := info.Normalized(p.mapper)
	if err != nil {
		return resource.Quantity{}, err
	}
	metricInfo := CustomMetricResource{
		CustomMetricInfo: info,
		NamespacedName:   name,
	}

	value := metricValue{
		labels: nil,
		value:  resource.Quantity{},
	}
	value.value.Set(int64(0))

	if info.Metric == Replicas {
		value.value.Set(int64(getReplicas(name.Name)))
	}

	p.values[metricInfo] = value

	return value.value, nil
}

// metricFor is a helper function which formats a value, metric, and object info into a MetricValue which can be returned by the metrics API
func (p *exampleProvider) metricFor(value resource.Quantity, name types.NamespacedName, selector labels.Selector, info provider.CustomMetricInfo, metricSelector labels.Selector) (*custom_metrics.MetricValue, error) {
	objRef, err := helpers.ReferenceFor(p.mapper, name, info)
	if err != nil {
		return nil, err
	}

	metric := &custom_metrics.MetricValue{
		DescribedObject: objRef,
		Metric: custom_metrics.MetricIdentifier{
			Name: info.Metric,
		},
		Timestamp: metav1.Time{time.Now()},
		Value:     value,
	}

	if len(metricSelector.String()) > 0 {
		sel, err := metav1.ParseToLabelSelector(metricSelector.String())
		if err != nil {
			return nil, err
		}
		metric.Metric.Selector = sel
	}

	return metric, nil
}

// metricsFor is a wrapper used by GetMetricBySelector to format several metrics which match a resource selector
func (p *exampleProvider) metricsFor(namespace string, selector labels.Selector, info provider.CustomMetricInfo, metricSelector labels.Selector) (*custom_metrics.MetricValueList, error) {
	names, err := helpers.ListObjectNames(p.mapper, p.client, namespace, selector, info)
	if err != nil {
		return nil, err
	}

	res := make([]custom_metrics.MetricValue, 0, len(names))
	for _, name := range names {
		namespacedName := types.NamespacedName{Name: name, Namespace: namespace}
		value, err := p.valueFor(info, namespacedName, metricSelector)
		if err != nil {
			if apierr.IsNotFound(err) {
				continue
			}
			return nil, err
		}

		metric, err := p.metricFor(value, namespacedName, selector, info, metricSelector)
		if err != nil {
			return nil, err
		}
		res = append(res, *metric)
	}

	return &custom_metrics.MetricValueList{
		Items: res,
	}, nil
}

func (p *exampleProvider) GetMetricByName(name types.NamespacedName, info provider.CustomMetricInfo, metricSelector labels.Selector) (*custom_metrics.MetricValue, error) {
	p.valuesLock.RLock()
	defer p.valuesLock.RUnlock()

	value, err := p.valueFor(info, name, metricSelector)
	if err != nil {
		return nil, err
	}
	return p.metricFor(value, name, labels.Everything(), info, metricSelector)
}

func (p *exampleProvider) GetMetricBySelector(namespace string, selector labels.Selector, info provider.CustomMetricInfo, metricSelector labels.Selector) (*custom_metrics.MetricValueList, error) {
	p.valuesLock.RLock()
	defer p.valuesLock.RUnlock()

	return p.metricsFor(namespace, selector, info, metricSelector)
}

func (p *exampleProvider) ListAllMetrics() []provider.CustomMetricInfo {
	p.valuesLock.RLock()
	defer p.valuesLock.RUnlock()

	return []provider.CustomMetricInfo{
		{
			GroupResource: schema.GroupResource{Group: "", Resource: "services"},
			Metric:        Replicas,
			Namespaced:    true,
		},
	}
}

func (p *exampleProvider) GetExternalMetric(namespace string, metricSelector labels.Selector, info provider.ExternalMetricInfo) (*external_metrics.ExternalMetricValueList, error) {
	p.valuesLock.RLock()
	defer p.valuesLock.RUnlock()

	matchingMetrics := []external_metrics.ExternalMetricValue{}
	for _, metric := range p.externalMetrics {
		if metric.info.Metric == info.Metric &&
			metricSelector.Matches(labels.Set(metric.labels)) {
			metricValue := metric.value
			metricValue.Timestamp = metav1.Now()
			matchingMetrics = append(matchingMetrics, metricValue)
		}
	}
	return &external_metrics.ExternalMetricValueList{
		Items: matchingMetrics,
	}, nil
}

func (p *exampleProvider) ListAllExternalMetrics() []provider.ExternalMetricInfo {
	p.valuesLock.RLock()
	defer p.valuesLock.RUnlock()

	externalMetricsInfo := []provider.ExternalMetricInfo{}
	for _, metric := range p.externalMetrics {
		externalMetricsInfo = append(externalMetricsInfo, metric.info)
	}
	return externalMetricsInfo
}

func getReplicas(service string) int64 {
	metrics := getReplicaMetrics()

	if metrics == nil {
		klog.Error("Metrics returned nil")
		return -1
	}
	klog.Infof("Number of replicas required %d ", metrics.Replicas)

	return int64(metrics.Replicas)
}

func getReplicaMetrics() *replicaMetrics {
	var uri = os.Getenv("SERVICE_URL")
	klog.Infof("URI", uri)

	// Can be uncommented and used for ssl verification.
	// caCert, err := ioutil.ReadFile("/opt/secrets/truststore.pem")
	// if err != nil {
	// 	klog.Fatal(err)
	// }
	// caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			// TLSClientConfig: &tls.Config{
			// 	RootCAs: caCertPool,
			// },
		},
	}

	emptyMetrics := replicaMetrics{
		Replicas: 0,
	}

	response, getError := client.Get(uri)
	if getError != nil {
		klog.Error(getError)
		return &emptyMetrics
	}

	if response.StatusCode >= 300 {
		klog.Error("Status code returned is: ", response.StatusCode)
		return &emptyMetrics
	}

	body, readError := ioutil.ReadAll(response.Body)
	if readError != nil {
		klog.Error(readError)
		return &emptyMetrics
	}

	stringBody := string(body)
	klog.Info(stringBody)

	metrics := &replicaMetrics{}
	parseError := json.Unmarshal([]byte(stringBody), &metrics)
	if parseError != nil {
		klog.Error("parsing error unmarshaling", parseError)
		return &emptyMetrics
	}

	klog.Info(metrics)

	return metrics
}
