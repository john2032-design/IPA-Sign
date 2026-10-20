FROM swift:6.3-jammy AS signer-build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 https://github.com/rorkai/rork-sign.git . && swift build -c release --product rorksign

FROM swift:6.3-jammy
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=signer-build /src/.build/release/rorksign /usr/local/bin/rorksign
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY server.js ./
COPY public ./public
RUN mkdir -p /data/work && chmod 0777 /data /data/work
ENV NODE_ENV=production
ENV DATA_DIR=/data
ENV RORKSIGN_BIN=/usr/local/bin/rorksign
ENV MAX_IPA_BYTES=4294967296
ENV PART_SIZE_BYTES=67108864
EXPOSE 10000
CMD ["node", "server.js"]
