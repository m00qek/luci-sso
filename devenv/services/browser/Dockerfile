ARG NODE_VERSION
FROM node:${NODE_VERSION}-alpine

# 1. Install Chromium, NSS tools, and dependencies
RUN apk add --no-cache \
    chromium \
    nss \
    nss-tools \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    wget \
    gettext

# 2. Configure Playwright to use system Chromium
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /app

# 3. Bake dependencies
COPY package.json .
RUN npm install
