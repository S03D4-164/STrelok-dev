#!/bin/bash

APP="strelok_app"
sudo rm -rf $APP/migrations
docker-compose run --rm web python manage.py makemigrations $APP
docker-compose run --rm web python manage.py migrate
docker-compose run --rm web python manage.py loaddata $APP/fixtures/1/* $APP/fixtures/2/*
docker-compose run --rm web python manage.py createsuperuser

