# Stage 1: Build frontend assets
FROM node:20-alpine AS frontend-build
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# Stage 2: Runtime
FROM python:3.13-slim
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

COPY --from=frontend-build /app/web/dist /app/web/dist

EXPOSE 8000

ENV MALWAR_DB_PATH=/app/data/malwar.db
VOLUME /app/data

CMD ["python", "-m", "malwar", "serve", "--host", "0.0.0.0"]
