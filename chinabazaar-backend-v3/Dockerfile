# Docker Hub yerine AWS ECR Public aynası (registry-1.docker.io erişim sorunlarına karşı)
FROM public.ecr.aws/docker/library/node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
COPY schema.sql ./
COPY migrations ./migrations
EXPOSE 3000
# Önce şemayı uygula, sonra API'yi başlat
CMD ["sh", "-c", "node src/migrate.js && node src/index.js"]
