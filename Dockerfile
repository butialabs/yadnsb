FROM node:22-slim

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production && npm cache clean --force

COPY . .

RUN groupadd -g 1001 nodejs && \
    useradd -r -u 1001 -g nodejs nodejs

RUN chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3000

CMD ["npm", "start"]
