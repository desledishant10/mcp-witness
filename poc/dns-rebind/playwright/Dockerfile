FROM mcr.microsoft.com/playwright:v1.60.0-noble

WORKDIR /app
COPY package.json /app/
RUN npm install --silent

COPY test.spec.js playwright.config.js /app/

CMD ["npx", "playwright", "test", "--reporter=list"]
