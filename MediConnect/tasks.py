from celery import shared_task
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from .models import Case, PandemicSignal
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
"""
from sentence_transformers import SentenceTransformer
from sklearn.cluster import AgglomerativeClustering
import numpy as np
"""
# On charge le modèle une seule fois (Modèle multilingue pour le français)
# model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
@shared_task
def task_analyze_signals():
    two_hours_ago = timezone.now() - timedelta(hours=2)
    
    """
    cases = Case.objects.filter(created_at__gte=two_hours_ago)
    if cases.count() < 3:
        return "Pas assez de cas pour analyser."
    # 1. Extraction des textes et des régions
    descriptions = [c.symptoms_description for c in cases]
    locations = [c.patient.address for c in cases]
    
    # 2. IA : Conversion des textes en vecteurs numériques (Embeddings)
    embeddings = model.encode(descriptions)

    # 3. IA : Clustering (On regroupe les symptômes qui se ressemblent à 80%+)
    # distance_threshold=0.2 signifie que si les phrases sont très proches, elles vont ensemble
    cluster_model = AgglomerativeClustering(
        n_clusters=None, 
        distance_threshold=0.4, 
        linkage='average'
    )
    labels = cluster_model.fit_predict(embeddings)

    # 4. Organisation des résultats par cluster et par région
    clusters = {}
    for i, label in enumerate(labels):
        region = locations[i]
        key = f"{label}_{region}"
        if key not in clusters:
            clusters[key] = {"count": 0, "texts": [], "region": region}
        clusters[key]["count"] += 1
        clusters[key]["texts"].append(descriptions[i])

    # 5. Création des signaux pour les clusters significatifs
    for key, data in clusters.items():
        if data["count"] >= 3:
            # On prend la description la plus courte comme "Titre" du groupe
            main_symptom = min(data["texts"], key=len)
            
            level = "Low"
            if data["count"] > 10: level = "Medium"
            if data["count"] > 25: level = "High"

            PandemicSignal.objects.update_or_create(
                symptom_type=f"Groupe IA: {main_symptom[:50]}...",
                region=data["region"],
                defaults={
                    'occurrence_count': data["count"],
                    'alert_level': level
                }
            )

    return f"Analyse IA terminée. {len(clusters)} clusters identifiés."
    """
    # Agrégation des symptômes par région
    stats = Case.objects.filter(created_at__gte=two_hours_ago).values(
        'patient__address', 'symptoms_description'
    ).annotate(total=Count('id'))

    for entry in stats:
        if entry['total'] >= 3:
            count = entry['total']
            level = "Low"
            if count > 10: level = "Medium"
            if count > 25: level = "High"

            PandemicSignal.objects.update_or_create(
                symptom_type=entry['symptoms_description'][:100],
                region=entry['patient__address'],
                defaults={
                    'occurrence_count': count,
                    'alert_level': level
                }
            )
    return f"Analysé {len(stats)} groupes de symptômes."

@shared_task
def task_send_email(subject, message, email,html_message,user):
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
        html_message=render_to_string(html_message, {'user': user}),
    )
    return f"Email envoyé à {email}."