FROM ubuntu:18.04

RUN apt-get update

RUN apt-get install -y python3.7
RUN apt-get install -y python3-pip
RUN useradd -m -s /bin/bash FlaskServer


COPY WHS /WHS

RUN chown -R FlaskServer:root WHS

WORKDIR /WHS/

RUN chmod 644 ./database/web.db
# EXPOSE 7000
RUN pip3 install Flask
RUN pip3 install flask_mail

WORKDIR /WHS/source

USER FlaskServer

CMD ["python3", "app.py"]