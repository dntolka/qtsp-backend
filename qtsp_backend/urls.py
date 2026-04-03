from django.contrib import admin
from django.urls import path
from qtsp.views import service_info, credentials_list, credentials_info, sign_hash

urlpatterns = [
    path('admin/', admin.site.urls),
    path('csc/v2/info', service_info),
    path('csc/v2/credentials/list', credentials_list),
    path('csc/v2/credentials/info', credentials_info),
    path('csc/v2/signatures/signHash', sign_hash),
]