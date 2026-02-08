FROM node:25-alpine

RUN apk add --no-cache curl ca-certificates gettext

WORKDIR /app

# Bake dependencies
COPY package.json .
RUN npm install --quiet && npm install -g nodemon

# Note: index.js and start.sh are mounted via docker-compose for dev