FROM registry.access.redhat.com/ubi7/ubi-minimal:latest
FROM golang

# The following labels are required for Redhat container certification
LABEL vendor="Kabanero" \
      name="Kabanero Rest Services" \
      summary="Image for Kabanaro Rest Servicesr" \
      description="This image contains the rest service for the Kabanero Foundation and Stacks.  See https://github.com/kabanero-io/kabanero-rest-services/"


# The licence must be here for Redhat container certification
COPY LICENSE /licenses/

USER 1001
RUN ls -l
#COPY cmd/kabanero-rest-services-server/main.go /usr/local/bin/main.go

ENV GOBIN $GOPATH/bin

ADD . /go/src/github.com/kabanero-io/kabanero-rest-services
RUN go install /go/src/github.com/kabanero-io/kabanero-rest-services/cmd/kabanero-rest-services-server/main
WORKDIR /go/src/github.com/kabanero-io/kabanero-rest-services
ENTRYPOINT /go/bin/main --port 9443
EXPOSE 9443

#RUN go run ./cmd/kabanero-rest-services-server/main.go --port 9443
#CMD ["go", "run", "cmd/kabanero-rest-services-server/main.go"] 
#CMD ["go", "run", "/usr/local/bin/main.go"] 


