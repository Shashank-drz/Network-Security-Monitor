# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Install build essentials, CMake, JSON & YAML libraries, and pkg-config
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    nlohmann-json3-dev \
    libyaml-cpp-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy all source files (CMakeLists.txt, src/ folder, rules/ folder) into the container
COPY . .

# Create a build directory and compile the project
RUN cmake -S . -B build && \
    cmake --build build --config Release

# Default command to run your engine
CMD ["./build/corr_engine"]
