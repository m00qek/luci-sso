ARG NODE_VERSION
ARG ALPINE_VERSION
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION}

RUN apk add --no-cache ca-certificates curl

WORKDIR /app
COPY package.json .
RUN npm install --quiet && npm install -g nodemon
