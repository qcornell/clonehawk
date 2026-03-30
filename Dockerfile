FROM node:20-alpine

RUN apk add --no-cache unzip wget

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --production

COPY . .

RUN mkdir -p .workspaces

ENV NODE_ENV=production
ENV PORT=3456

EXPOSE 3456

CMD ["node", "server.js"]
