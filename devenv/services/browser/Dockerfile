ARG NODE_VERSION
ARG ALPINE_VERSION
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION}

# 1. Install Chromium, NSS tools, and dependencies
RUN apk add --no-cache \
  chromium \
  nss \
  nss-tools \
  freetype \
  harfbuzz \
  ttf-freefont \
  ca-certificates \
  curl

# 2. Configure Playwright to use system Chromium
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /app
COPY package.json .
RUN npm install --quiet
