import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

app = Celery('MediConnect')

# Utilise Redis comme Broker
app.config_from_object('django.conf:settings', namespace='CELERY')

# Configuration de la tâche périodique (toutes les 2h)
app.conf.beat_schedule = {
    'analyze-symptoms-every-2h': {
        'task': 'MediConnect.tasks.task_analyze_signals',
        'schedule': crontab(minute=0, hour='*/2'),
    },
}

app.autodiscover_tasks()