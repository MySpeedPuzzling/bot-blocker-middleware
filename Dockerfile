FROM --platform=$BUILDPLATFORM node:22-alpine AS geodb

WORKDIR /build
COPY scripts/build-geodb.mjs scripts/
# Compiles DB-IP lite (country+ASN) into binary range files. Fails OPEN: on
# download failure it ships an empty meta.json and the middleware runs with
# geo/ASN risk signals disabled. The monthly scheduled CI rebuild refreshes it.
RUN node scripts/build-geodb.mjs /build/geodb

FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production
COPY server.js ./
COPY --from=geodb /build/geodb ./geodb

EXPOSE 3000

CMD ["node", "server.js"]
