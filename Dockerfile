# === FILE 3: Dockerfile ===
# Save this as Dockerfile in your project root

FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application
COPY server.js .
COPY schema.sql .

# Create file storage directory
RUN mkdir -p file_storage

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/v1/auth/me', (r) => {if (r.statusCode !== 401) throw new Error(r.statusCode)})"

# Start application
CMD ["node", "server.js"]
