FROM nginx:alpine

# nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# copy all static site files (index + standalone pages + assets)
WORKDIR /usr/share/nginx/html
COPY . .

EXPOSE 80