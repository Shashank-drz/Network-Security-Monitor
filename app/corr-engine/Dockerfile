FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    nlohmann-json3-dev \
    libyaml-cpp-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cmake -S . -B build && cmake --build build --config Release

CMD ["./build/corr_engine"]
