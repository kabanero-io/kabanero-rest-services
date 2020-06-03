FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

# The following labels are required for Redhat container certification
LABEL vendor="Kabanero" \
      name="Kabanero Rest Services" \
      summary="Image for Kabanaro Rest Servicesr" \
      description="This image contains the rest service for the Kabanero Foundation and Stacks.  See https://github.com/kabanero-io/kabanero-rest-services/"

# The licence must be here for Redhat container certification
COPY LICENSE /licenses/

USER root
COPY build/bin /usr/local/bin
RUN chmod -R 777 /usr/local/bin
COPY build/bin/entrypoint /usr/local/bin/entrypoint

RUN echo 'right before entrypoint stuff: '
RUN ls -l /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint


# RUN echo 'right before copy of main.go'
# COPY build/bin/kabanero-rest-services /usr/local/bin/kabanero-rest-services
# RUN chmod +x /usr/local/bin/kabanero-rest-services

USER 1001

ENTRYPOINT ["/usr/local/bin/entrypoint"]
