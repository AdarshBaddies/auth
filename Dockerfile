# Use official Node.js LTS image
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy the run.sh script into the container
COPY run.sh /app/run.sh

# Make the script executable
RUN chmod +x /app/run.sh

# Copy source code
COPY . .

# Install wait-for-it for waiting for the DB
RUN apk add --no-cache bash

ENTRYPOINT ["/app/run.sh"]

# Expose port
EXPOSE 5000

# Start server
CMD ["npm", "start"]
