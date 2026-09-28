FROM node:latest
ARG NPM_TOKEN
ENV DATABASE_PASSWORD=hunter2
WORKDIR /app
RUN apt-get update && apt-get install curl -y
COPY . .
RUN npm install
EXPOSE 3000
CMD npm start
