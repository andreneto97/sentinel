FROM node:latest
ENV API_TOKEN=sk-supersecret
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "index.js"]
