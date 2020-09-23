
### Running sample HPA application
```
eval $(minikube docker-env) 
docker build -t k8s-sample-app:1 .
kubectl apply -f app-deploy.yml