from django.contrib.gis import admin
from .models import Profile, Photo, Group, Match, VerificationCode

# Register your models here.
admin.site.register(Profile, admin.GISModelAdmin)
admin.site.register(Photo, admin.GISModelAdmin)
admin.site.register(Match, admin.GISModelAdmin)
admin.site.register(Group, admin.GISModelAdmin)
admin.site.register(VerificationCode, admin.GISModelAdmin)
