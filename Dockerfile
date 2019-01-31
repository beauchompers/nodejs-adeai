FROM node:boron
LABEL Description="This container runs the Active Directory EAI Application"
ENV REFRESHED_AT 2019-01-01

# Set Node env
ENV NODE_ENV production

# Create node app directory
RUN mkdir -p /home/node/app
WORKDIR /home/node/app

# Install app dependencies
COPY package.json /home/node/app/
RUN npm install

# Copy node app files
COPY . /home/node/app
COPY bin /home/node/app/bin
COPY views /home/node/app/views
COPY routes /home/node/app/routes
COPY public /home/node/app/public

RUN chown -R node:node /home/node/*

# Always run as the node user
USER node

# Expose port on the container
EXPOSE 3000

# Health check only works when NODE_ENV=production
HEALTHCHECK --interval=30s --timeout=3s CMD curl -k --fail https://localhost:3000/login || exit 1

# Start node on container startup
CMD [ "npm", "start" ]
