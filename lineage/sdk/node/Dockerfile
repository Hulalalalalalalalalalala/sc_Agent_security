FROM node:20-alpine
WORKDIR /app
COPY package.json lct_sdk.mjs lct_sdk.d.ts example_agent.mjs /app/
ENTRYPOINT ["node", "/app/example_agent.mjs", "--port", "9001"]
