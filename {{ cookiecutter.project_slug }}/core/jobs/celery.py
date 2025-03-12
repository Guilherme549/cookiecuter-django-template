import os
import environ
from pathlib import Path
from celery import Celery

env = environ.Env(DEBUG=(bool, False))

BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(os.path.join(BASE_DIR, ".env"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

app = Celery("all-control")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
app.conf.beat_scheduler = "django_celery_beat.schedulers.DatabaseScheduler"

REDIS_CELERY_URL = env("REDIS_CELERY_URL", default=None)
app.conf.broker_url = REDIS_CELERY_URL


@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    pass
