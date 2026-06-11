FROM mcr.microsoft.com/playwright:v1.55.0-noble

WORKDIR /app
COPY package.json /app/
RUN npm install --silent

COPY test.spec.js /app/

CMD ["npx", "playwright", "test", "--reporter=list"]
