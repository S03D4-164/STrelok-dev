FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
#ADD requirements.txt /code/
#RUN pip install -r requirements.txt
RUN pip install Django psycopg2 stix2 dotmap requests django_datatables_view
ADD . /code/
