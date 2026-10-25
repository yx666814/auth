# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /build

# Copy manifests first so dependency installation is cached independently of
# source edits.
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund

COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npm run build

# ---- runtime stage ---------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# The stock image runs the master as root to bind :80. It is bound to 8080
# here instead, and the whole process tree runs as the unprivileged nginx
# user, which also makes the container safe under read_only: true.
RUN sed -i '/^user /d; s#^pid .*#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf \
    && rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/app.conf
COPY --from=build /build/dist /usr/share/nginx/html

USER nginx
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
