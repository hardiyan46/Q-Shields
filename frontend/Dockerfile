FROM node:20-alpine

WORKDIR /app

# Install dependencies first for Docker layer caching
COPY package.json ./
RUN npm install

# Copy remaining frontend source files
COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
