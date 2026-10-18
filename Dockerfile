FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY backend/app ./app
COPY --from=ui /ui/dist /frontend
RUN useradd --uid 10001 --create-home autominer
USER autominer
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
