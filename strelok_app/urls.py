from django.conf.urls import url, include
from django.contrib import admin, auth

from .views.sdo import sdo_list,sdo_view
from .views.observables import obs_view
from .views.drs import viz_drs, data_drs
from .views.stix import stix_view ,stix2_json, stix2type_json
from .views.taxii import taxii_discovery, taxii_collection, taxii_get_objects
#from .views.timeline import viz_timeline, data_timeline, timeline_view
from .views.timeline import timeline_view
from .views.chart import kill_chain_view, ttp_view, target_chart, actor_chart
#from .views.auth import logout_view
from .tables import *

from two_factor.admin import AdminSiteOTPRequired
#admin.site.__class__ = AdminSiteOTPRequired

urlpatterns = [
    url(r'', include('two_factor.urls', 'two_factor')),
    url(r'^account/', include('django.contrib.auth.urls')),
    url(r'^admin/', admin.site.urls),
    url(r'^data/attack-pattern/', AttackPatternData.as_view(), name="attackpattern_data"),
    url(r'^data/campaign/', CampaignData.as_view(), name="campaign_data"),
    url(r'^data/course-of-action/', CourseOfActionData.as_view(), name="courseofaction_data"),
    url(r'^data/identity/', IdentityData.as_view(), name="identity_data"),
    url(r'^data/intrusion-set/', IntrusionSetData.as_view(), name="intrusionset_data"),
    url(r'^data/malware/', MalwareData.as_view(), name="malware_data"),
    url(r'^data/observed-data/', ObservedDataData.as_view()),
    url(r'^data/report/', ReportData.as_view(), name="report_data"),
    url(r'^data/threat-actor/', ThreatActorData.as_view(), name="threatactor_data"),
    url(r'^data/tool/', ToolData.as_view(), name="tool_data"),
    url(r'^data/vulnerability/', VulnerabilityData.as_view(), name="vulnerability_data"),
    url(r'^data/relationship/', RelationshipData.as_view(), name="relationship_data"),
    url(r'^data/sighting/', SightingData.as_view(), name="sighting_data"),
    url(r'^data/indicator/', IndicatorData.as_view(), name="inicator_data"),
    url(r'^data/observable/', ObservableObjectData.as_view()),
    url(r'^data/pattern/', IndicatorPatternData.as_view(), name="pattern_data"),
    url(r'^data/drs/$', data_drs),
    url(r'^chart/target/(?P<cnt_by>[a-z]+)$', target_chart),
    url(r'^chart/threat-actor/(?P<cnt_by>[a-z]+)$', actor_chart),
    #url(r'^data/timeline/$', data_timeline),
    url(r'^stix/$', stix_view),
    url(r'^stix/drs/$', viz_drs),
    #url(r'^stix/matrix/$', kill_chain_view),
    url(r'^stix/matrix/$', ttp_view),
    url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)\.json$', stix2_json),
    url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)', sdo_view),
    url(r'^stix/all.json$', stix2_json),
    url(r'^stix/(?P<type>[^/]+)\.json$', stix2type_json),
    url(r'^stix/(?P<type>[^/]+)', sdo_list),
    url(r'^timeline/(?P<id>[a-z\-]+--[0-9a-f\-]+)$', timeline_view),
    url(r'^timeline/$', timeline_view),
    url(r'^observable/(?P<id>[^/]+)', obs_view),
    url(r'^taxii/api/collections/(?P<id>[^/]+)/id/(?P<object_id>[^/]+)/$', taxii_collection),
    url(r'^taxii/api/collections/(?P<id>[^/]+)/objects/$', taxii_get_objects),
    url(r'^taxii/api/collections/(?P<id>[^/]+)/$', taxii_collection),
    url(r'^taxii/api/collections/$', taxii_collection),
    url(r'^taxii/$', taxii_discovery),
    url(r'^$', viz_drs),
]
