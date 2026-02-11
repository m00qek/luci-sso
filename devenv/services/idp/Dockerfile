ARG NODE_VERSION=25
ARG ALPINE_VERSION=3.23
FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION}

RUN apk add --no-cache ca-certificates curl

WORKDIR /app
COPY package.json .
RUN npm install --quiet && npm install -g nodemon
