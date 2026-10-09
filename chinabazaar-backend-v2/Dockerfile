FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY schema.sql ./
EXPOSE 3000
# Önce şemayı uygula, sonra API'yi başlat
CMD ["sh", "-c", "node src/migrate.js && node src/index.js"]
