from django.contrib import admin

from .models import *

admin.site.register(STIXObjectType)
admin.site.register(STIXObjectID)
admin.site.register(RelationshipType)
admin.site.register(Relationship)
admin.site.register(DefinedRelationship)
admin.site.register(ReportLabel)
admin.site.register(Report)
admin.site.register(IdentityLabel)
admin.site.register(IndustrySector)
admin.site.register(Identity)
admin.site.register(Indicator)
admin.site.register(IndicatorPattern)
admin.site.register(AttackPattern)
admin.site.register(MalwareLabel)
admin.site.register(Malware)
admin.site.register(ThreatActorLabel)
admin.site.register(ThreatActorAlias)
admin.site.register(ThreatActor)
admin.site.register(Sighting)
admin.site.register(Tool)
admin.site.register(ToolLabel)
admin.site.register(TaxiiCollection)
admin.site.register(Campaign)
admin.site.register(ObservableObjectType)
admin.site.register(ObservablePropertyName)
admin.site.register(ObservableProperty)
admin.site.register(ObservableObject)
