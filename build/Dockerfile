FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

# The following labels are required for Redhat container certification
LABEL vendor="Kabanero" \
      name="Kabanero Rest Services" \
      summary="Image for Kabanaro Rest Servicesr" \
      description="This image contains the rest service for the Kabanero Foundation and Stacks.  See https://github.com/kabanero-io/kabanero-rest-services/"

# The licence must be here for Redhat container certification
COPY LICENSE /licenses/

USER root
RUN chmod -R 777 /usr/local/bin
RUN echo 'right before copy of main.go'
COPY build/_output/bin/kabanero-rest-services/main /usr/local/bin/main
COPY build/bin /usr/local/bin
USER 1001

ENTRYPOINT ["/usr/local/bin/entrypoint"]
