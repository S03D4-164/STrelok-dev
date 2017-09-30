from django.conf.urls import url, include
from django.contrib import admin

from .views.sdo import sdo_list,sdo_view, obs_view
from .views.drs import viz_drs, data_drs
from .views.stix import stix_view ,stix2_json, stix2type_json
from .views.taxii import taxii_discovery, taxii_collection, taxii_get_objects
#from .views.timeline import viz_timeline, data_timeline, timeline_view
from .views.timeline import timeline_view
from .views.chart import chart_view, kill_chain_view
from .views.auth import logout_view
from .tables import *

from two_factor.admin import AdminSiteOTPRequired
admin.site.__class__ = AdminSiteOTPRequired

urlpatterns = [
    url(r'', include('two_factor.urls', 'two_factor')),
    url(r'^account/logout$', logout_view),
    url(r'^stix/$', stix_view),
    url(r'^admin/', admin.site.urls),
    url(r'^data/report/', ReportData.as_view(), name="report_data"),
    url(r'^data/threat-actor/', ThreatActorData.as_view(), name="threatactor_data"),
    url(r'^data/identity/', IdentityData.as_view(), name="identity_data"),
    url(r'^data/indicator/', IndicatorData.as_view(), name="inicator_data"),
    url(r'^data/observable/', ObservableObjectData.as_view()),
    url(r'^data/pattern/', IndicatorPatternData.as_view(), name="pattern_data"),
    url(r'^data/campaign/', CampaignData.as_view(), name="campaign_data"),
    url(r'^data/drs/$', data_drs),
    #url(r'^data/timeline/$', data_timeline),
    url(r'^data/malware/', MalwareData.as_view(), name="malware_data"),
    url(r'^data/tool/', ToolData.as_view(), name="tool_data"),
    url(r'^stix/chart', chart_view),
    url(r'^stix/drs/$', viz_drs),
    url(r'^stix/matrix/$', kill_chain_view),
    url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)\.json$', stix2_json),
    url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)', sdo_view),
    url(r'^stix/all.json$', stix2_json),
    url(r'^stix/(?P<type>[^/]+)\.json$', stix2type_json),
    url(r'^stix/(?P<type>[^/]+)', sdo_list),
    url(r'^observable/(?P<id>[^/]+)', obs_view),
    url(r'^taxii/api/collections/(?P<id>[^/]+)/id/(?P<object_id>[^/]+)/$', taxii_collection),
    url(r'^taxii/api/collections/(?P<id>[^/]+)/objects/$', taxii_get_objects),
    url(r'^taxii/api/collections/(?P<id>[^/]+)/$', taxii_collection),
    url(r'^taxii/api/collections/$', taxii_collection),
    url(r'^taxii/$', taxii_discovery),
    url(r'^$', viz_drs),
    url(r'^timeline/(?P<id>[a-z\-]+--[0-9a-f\-]+)$', timeline_view),
    url(r'^timeline/$', timeline_view),
]