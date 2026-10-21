FROM node:22-bookworm AS zsign-build
ARG ZSIGN_VERSION=1.1.2
RUN apt-get update \
    && apt-get install -y --no-install-recommends git g++ make pkg-config libssl-dev ca-certificates binutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY scripts/patch-zsign-progress.mjs /tmp/patch-zsign-progress.mjs
RUN git clone --depth 1 --branch v${ZSIGN_VERSION} https://github.com/zhlynn/zsign.git . \
    && node /tmp/patch-zsign-progress.mjs /src/src/bundle.cpp \
    && cd build/linux \
    && make clean \
    && make VERSION=${ZSIGN_VERSION} -j2 \
    && cd /src \
    && strip bin/zsign \
    && ./bin/zsign -v

FROM node:22-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 dpkg unzip python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=zsign-build /src/bin/zsign /usr/local/bin/zsign
RUN mkdir -p /usr/share/licenses/zsign
COPY --from=zsign-build /src/LICENSE /usr/share/licenses/zsign/LICENSE
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY server.js ./
COPY lib ./lib
COPY docs ./docs
RUN mkdir -p /data/work && chmod 0777 /data /data/work
ENV NODE_ENV=production
ENV DATA_DIR=/data
ENV ZSIGN_BIN=/usr/local/bin/zsign
ENV MAX_IPA_BYTES=4294967296
ENV PART_SIZE_BYTES=67108864
EXPOSE 10000
CMD ["node", "server.js"]
