# This is a workaround until manfistival can interact with the virtual file system
ARG IMAGE=kabanero-rest-services:latest

FROM ${IMAGE}

# The following labels are required for Redhat container certification
LABEL vendor="Kabanero" \
      name="Kabanero Rest Services" \
      summary="Image for Kabanaro Rest Servicesr" \
      description="This image contains the rest service for the Kabanero Foundation and Stacks.  See https://github.com/kabanero-io/kabanero-rest-services/"

COPY config /config

# The licence must be here for Redhat container certification
COPY LICENSE /licenses/