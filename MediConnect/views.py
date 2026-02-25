from django.shortcuts import render
from .models import DashboardInfo, Appointment, MedicalRecord, Message
from django.utils import timezone

# Create your views here.

def patient_index(request):
    """
    Vue pour la page d'accueil des patients.
    """
    today = timezone.now().date()
    dashboard_infos = DashboardInfo.objects.filter(is_active=True).order_by('-created_at')
    upcoming_appointments = Appointment.objects.filter(status='SCHEDULED', date__gte=today).order_by('date', 'time')[:5]
    recent_records = MedicalRecord.objects.all().order_by('-date')[:3]
    recent_messages = Message.objects.all().order_by('-created_at')[:5]
    
    context = {
        'dashboard_infos': dashboard_infos,
        'upcoming_appointments': upcoming_appointments,
        'recent_records': recent_records,
        'recent_messages': recent_messages,
    }
    return render(request, 'MediConnect/index.html', context)
