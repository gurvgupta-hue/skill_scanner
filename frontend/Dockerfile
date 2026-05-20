FROM node:18-alpine

WORKDIR /app

# Copy lockfile first so npm ci can enforce exact versions
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

EXPOSE 3005

CMD ["npm", "run", "start", "--", "-p", "3005"]