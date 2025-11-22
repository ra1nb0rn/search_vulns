FROM ubuntu:latest

WORKDIR /home/search_vulns
RUN apt-get update >/dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip tzdata locales sudo wget git build-essential gcc >/dev/null && \
    git clone --quiet --depth 1 https://github.com/ra1nb0rn/search_vulns.git . && \
    pip3 install -e . --break-system-packages && \
    search_vulns --full-install && \
    search_vulns -u && \
    rm -rf /var/lib/apt/lists/*

RUN sed -i -e "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/" /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8   
