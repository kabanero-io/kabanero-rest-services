#swagger generate server -A kabanero-rest-services -f swagger.yml
echo "Building kabanero/kabanero-rest-services:$1"
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/kabanero-rest-services-server/
cp build/_output/bin/kabanero-rest-services/main bin/.
cp build/_output/bin/kabanero-rest-services/main build/bin/.
cp kabanero-rest-services-server build/bin/.
docker rmi -f kabanero/kabanero-rest-services:$1
docker build -f build/Dockerfile -t kabanero/kabanero-rest-services:$1 .
docker push kabanero/kabanero-rest-services:$1
