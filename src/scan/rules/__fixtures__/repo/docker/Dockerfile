FROM node:latest
ARG NPM_TOKEN
ENV API_SECRET=s3cret
WORKDIR /app
RUN apt-get update && apt-get install -y curl
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "dist/index.js"]
