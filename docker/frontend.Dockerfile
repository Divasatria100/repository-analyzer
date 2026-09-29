# RepoLens frontend — local development image.
#
# Runs RepoLens's own Vite development server only. It never executes
# analyzed repository content.

FROM node:24-slim

ENV NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /srv/frontend

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
