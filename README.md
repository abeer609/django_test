# django_test
Install the required package.
```shell
pip install -r requirements.txt
```
Migrate models
```shell
python manage.py migrate
```
smtp4dev is used as fake smtp server.
```shell
docker run --rm -it -p 3000:80 -p 2525:25 rnwood/smtp4dev
```
Create .env file in root project and set the Environment variables. 
```shell
SECRET_KEY=
DB_NAME=
DB_USER=
DB_PASSWORD=
DB_HOST=
DB_PORT=
EMAIL_HOST=
EMAIL_PORT=
EMAIL_HOST_USER=
DEFAULT_FROM_EMAIL=
```
