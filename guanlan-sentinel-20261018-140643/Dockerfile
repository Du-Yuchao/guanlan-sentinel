FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json server.mjs ./
COPY lib ./lib
COPY static ./static
COPY data/verified_sources.json ./data/verified_sources.json
ENV HOST=0.0.0.0 PORT=8787 SENTINEL_DATA_DIR=/app/data/runtime
RUN mkdir -p /app/data/runtime && chown -R node:node /app
USER node
EXPOSE 8787
VOLUME ["/app/data/runtime"]
CMD ["node", "--experimental-sqlite", "server.mjs"]

