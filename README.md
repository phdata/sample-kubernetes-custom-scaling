# sample-kubernetes-custom-scaling

This application can be used as a starting point and an example for creating a custom scaling api from an application to scale in kubernetes. 

The k8s scaling app is an example application that will expose an API for use by kubernetes.

The autoscaler api is a pod that will interact with a Horizontal pod scaler, the kubernetes api, and the sample app to all if to scale for the requested amount.
