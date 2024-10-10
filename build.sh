set -o errxit 

pip install -r requirements.txt

python manage.py collectsatic --no-input 

python manage.py migrate 