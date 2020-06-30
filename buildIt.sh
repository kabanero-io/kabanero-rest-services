#swagger generate server -A kabanero-rest-services -f swagger.yml
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/kabanero-rest-services-server/
cp build/_output/bin/kabanero-rest-services/main bin/.
cp build/_output/bin/kabanero-rest-services/main build/bin/.
cp kabanero-rest-services-server build/bin/.
docker rmi -f davco01a/kabanero-rest-services:latest
docker build -f build/Dockerfile -t davco01a/kabanero-rest-services:latest .
docker push davco01a/kabanero-rest-services:latest
