# MediConnect

MediConnect est une plateforme de santé qui permet aux patients de prendre rendez-vous avec des médecins et de consulter des médecins en ligne.

## Technologies utilisées(back-end)

- Python 3.12
- Django 5.2
- Django REST framework 4.2
- Redis
- Celery

## Installation

```bash
source venv/bin/activate
```

```bash
pip install -r requirements.txt
```

```bash
python manage.py migrate
```
```bash
python manage.py createsuperuser
```

```bash
celery -A core worker -l info
```

```bash
celery -A core beat -l info
```

```bash
python manage.py runserver
```





