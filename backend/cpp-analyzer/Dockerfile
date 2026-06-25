FROM gcc:13-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cmake -S . -B build && cmake --build build

RUN mkdir -p logs

CMD ["./build/cpp_analyzer"]
