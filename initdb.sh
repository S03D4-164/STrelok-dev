sudo rm -rf STreifen/migrations
docker-compose run --rm web python manage.py makemigrations STreifen
docker-compose run --rm web python manage.py migrate
docker-compose run --rm web python manage.py loaddata STreifen/fixtures/1/* STreifen/fixtures/2/*
docker-compose run --rm web python manage.py createsuperuser

