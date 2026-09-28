FROM node:20-alpine AS base
WORKDIR /app
COPY . .
RUN npm ci && npm run build
CMD ["npm", "start"]
