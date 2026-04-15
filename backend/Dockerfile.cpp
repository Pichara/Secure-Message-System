FROM ubuntu:22.04 AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     build-essential \
     cmake \
     git \
     ca-certificates \
     pkg-config \
     libpq-dev \
     libpqxx-dev \
     libsodium-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY CMakeLists.txt ./
COPY src ./src

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build -j

FROM ubuntu:22.04
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     libpq5 \
     libpqxx-dev \
     libsodium23 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/build/secure_message_backend /app/secure_message_backend

EXPOSE 8080
ENV PORT=8080

CMD ["/app/secure_message_backend"]
