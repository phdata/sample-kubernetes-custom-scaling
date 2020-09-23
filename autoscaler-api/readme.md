
Create the Docker image and deploy it to minikube.
```
eval $(minikube docker-env) 
docker build -t k8s-custom-api:1 .
kubectl apply -f custom_metric_setup.yml
kubectl apply -f custom_metrics_server_deploy.yml
```

To confirm the hpa is work run the below command. 

```
kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1/namespaces/default/service/sample-metrics-app/replicas | jq 
```
