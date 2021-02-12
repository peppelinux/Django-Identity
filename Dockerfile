FROM alpine:3.13.0

COPY djangosaml2_sp/ /run/django-identity/djangosaml2_sp/
WORKDIR /run/django-identity/djangosaml2_sp/

RUN apk update
RUN apk add build-base git py3-pip python3 python3-dev libffi-dev openssl-dev cargo xmlsec-dev mysql-client py3-mysqlclient
RUN ln -s /usr/bin/python3 /usr/bin/python

RUN pip install -U setuptools pip
RUN pip install -r requirements.txt

CMD ./run.sh
