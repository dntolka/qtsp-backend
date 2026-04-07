from django.contrib import admin
from django.urls import path
from qtsp.views import service_info, credentials_list, credentials_info, sign_hash, credentials_revoke, revocation_list, oid4vp_authorize, oid4vp_response

urlpatterns = [
    path('admin/', admin.site.urls),
    path('csc/v2/info', service_info),
    path('csc/v2/credentials/list', credentials_list),
    path('csc/v2/credentials/info', credentials_info),
    path('csc/v2/signatures/signHash', sign_hash),
    path('csc/v2/credentials/revoke', credentials_revoke),
    path('csc/v2/credentials/revocationlist', revocation_list),
    path('oid4vp/authorize', oid4vp_authorize),
    path('oid4vp/response', oid4vp_response),
]