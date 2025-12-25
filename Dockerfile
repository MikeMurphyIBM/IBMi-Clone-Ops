# Use Debian so date & commands behave consistently
FROM debian:stable-slim
SHELL ["/bin/bash", "-c"]  
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root
WORKDIR ${HOME}

# -----------------------------------------------------------
# Install base dependencies & GNU coreutils
# -----------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    jq \
    ca-certificates \
    coreutils \
    moreutils \
    openssh-client \
 && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------
# Install IBM Cloud CLI
# -----------------------------------------------------------
RUN curl -fsSL https://clis.cloud.ibm.com/install/linux | bash

# Ensure IBM Cloud CLI is available
ENV PATH="/usr/local/ibmcloud/bin:/root/.bluemix:$PATH"

# -----------------------------------------------------------
# Install required IBM Cloud plugins
# -----------------------------------------------------------
# Disable version check (avoids build failures)
RUN ibmcloud config --check-version=false

# Initialize plugin repository list
RUN ibmcloud plugin repo-plugins

# Install PowerVS + Code Engine plugins
RUN ibmcloud plugin install power-iaas -f
RUN ibmcloud plugin install code-engine -f

# -----------------------------------------------------------
# Copy script into container
# -----------------------------------------------------------
COPY job-1-2-merged.sh /job-1-2-merged.sh

# Normalize line endings + ensure script is executable
RUN sed -i 's/\r$//' /job-1-2-merged.sh && chmod +x /job-1-2-merged.sh

# -----------------------------------------------------------
# Run the script
# -----------------------------------------------------------
CMD ["/job-1-2-merged.sh"]
