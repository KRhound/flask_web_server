FROM ubuntu/apache2:latest

COPY ./sources/index.html /var/www/html
COPY ./sources/flag.txt /var/www/html
COPY ./sources/js.js /var/www/html
COPY ./sources/README.txt /var/www/html
COPY ./sources/style.css /var/www/html
