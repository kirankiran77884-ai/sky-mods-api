FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY src ./src

RUN mkdir -p /app/data

EXPOSE 8080

CMD ["node", "src/server.js"]
