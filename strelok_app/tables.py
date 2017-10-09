from django_datatables_view.base_datatable_view import BaseDatatableView
from django.apps import apps
from .models import *
from .forms import *


def _get_row_from_column(column, row):
    if column == 'id':
        return '<a class="btn btn-default btn-xs">{0}</button>'.format(row.id)
    elif column == 'name':
        return '<a href="/stix/{0}">{1}</a>'.format(row.object_id.object_id,row.name)
    elif column == 'aliases':
        a = []
        for alias in row.aliases.all():
            if not alias.name in a:
                a.append(alias.name)
        return " / ".join(a)
    elif column == 'kill_chain_phases':
        k = []
        for kcp in row.kill_chain_phases.all():
            if not kcp.phase_name in k:
                k.append(kcp.phase_name)
        return " / ".join(k)
    elif column == 'labels':
        l = []
        for label in row.labels.all():
            if not label.value in l:
                l.append(label.value)
        return " / ".join(l)
    elif column == 'publisher':
        p = Identity.objects.filter(object_id=row.created_by_ref)
        if p.count() == 1:
            return p[0].name
        else:
            return None
    elif column == 'object_refs':
        return row.object_refs.count()
    elif column == 'created_by_ref':
        name = ""
        if row.created_by_ref:
            c = get_obj_from_id(row.created_by_ref)
            name = c.name
        return name
    return False

class AttackPatternData(BaseDatatableView):
    model = AttackPattern
    columns = ['created', 'name', 'kill_chain_phases']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(AttackPatternData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(kill_chain_phases__phase_name__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class CampaignData(BaseDatatableView):
    model = Campaign
    columns = ['created', 'name', 'aliases', 'first_seen']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(CampaignData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(aliases__name__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()


class CourseOfActionData(BaseDatatableView):
    model = CourseOfAction
    columns = ['created', 'name', 'description']
    order_columns = ['created', 'name', 'description']
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(CourseOfActionData, self).render_column(row, column)
        else:
            return result

class IdentityData(BaseDatatableView):
    model = Identity
    columns = ['created', 'name', 'sectors', 'labels']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'name':
            if self.request.user.is_authenticated():
                return '<a href="/stix/{0}">{1}</a>'.format(row.object_id.object_id,row.name)
            else:
                return '<a href="/stix/{0}">{0}</a>'.format(row.object_id.object_id,row.name)
        elif column == 'labels':
            l = ""
            for label in row.labels.all():
                l += label.value+"<br>"
            return l
        elif column == 'sectors':
            s = ""
            for sector in row.sectors.all():
                s += sector.value+"<br>"
            return s
        else:
            return super(IdentityData, self).render_column(row, column)
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(sectors__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class IntrusionSetData(BaseDatatableView):
    model = IntrusionSet
    columns = ['created', 'name', 'aliases', 'first_seen']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(IntrusionSetData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(aliases__name__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class MalwareData(BaseDatatableView):
    model = Malware
    columns = ['created', 'name', 'labels', 'kill_chain_phases']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(MalwareData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(labels__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class ObservedDataData(BaseDatatableView):
    model = ObservedData
    columns = ['created', 'object_id', 'observable_objects']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'object_id':
            return "<a href=/stix/{0}>{0}</href>".format(row.object_id.object_id)
        elif column == 'observable_objects':
            results = []
            for obs in row.observable_objects.all():
                t = obs.type.name
                if obs.type.model_name:
                    m = apps.get_model(obs._meta.app_label, obs.type.model_name)
                    o = m.objects.get(id=obs.id)
                    if hasattr(o, "name"):
                        results.append(t + ":" + o.name)
                    elif hasattr(o, "value"):
                        results.append(t + ":" + o.value)
            return results
        else:
            return super(ObservedDataData, self).render_column(row, column)

class ReportData(BaseDatatableView):
    model = Report
    columns = ['created', 'name', 'created_by_ref', 'published']
    order_columns = columns
    max_display_length = 100

    def get_initial_queryset(self):
        qs = Report.objects.all()
        return qs
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(ReportData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(published__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class ThreatActorData(BaseDatatableView):
    model = ThreatActor
    columns = ['created', 'name', 'aliases']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(ThreatActorData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(aliases__name__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class ToolData(BaseDatatableView):
    model = Tool
    columns = ['created', 'name', 'labels', 'kill_chain_phases']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(ToolData, self).render_column(row, column)
        else:
            return result
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(labels__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class VulnerabilityData(BaseDatatableView):
    model = Vulnerability
    columns = ['created', 'name', 'description']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        result = _get_row_from_column(column, row)
        if result == False:
            return super(VulnerabilityData, self).render_column(row, column)
        else:
            return result

# SRO
class RelationshipData(BaseDatatableView):
    model = Relationship
    columns = ['created', 'object_id', 'source_ref', 'relationship_type', 'target_ref']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'source_ref':
            o = get_obj_from_id(row.source_ref)
            return "<a href=/stix/{0}>{1}</href>".format(row.object_id.object_id, o)
        elif column == 'target_ref':
            o = get_obj_from_id(row.target_ref)
            return "<a href=/stix/{0}>{1}</href>".format(row.object_id.object_id, o)
        elif column == 'relationship_type':
            return row.relationship_type.name
        elif column == 'object_id':
            return "<a href=/stix/{0}>{1}</href>".format(row.object_id.object_id, row.object_id.object_id)
        else:
            return super(RelationshipData, self).render_column(row, column)

class SightingData(BaseDatatableView):
    model = Sighting
    columns = ['created', 'object_id', 'where_sighted_refs', 'sighting_of_ref']
    order_columns = columns
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'sighting_of_ref':
            o = get_obj_from_id(row.sighting_of_ref)
            return "<a href=/stix/{0}>{1}</href>".format(row.object_id.object_id, o)
        elif column == 'where_sighted_refs':
            wsr = ""
            for r in row.where_sighted_refs.all():
                o = get_obj_from_id(r.object_id)
                wsr += "<a href=/stix/{0}>{1}</href><br>".format(r.object_id, o)
            return wsr
        elif column == 'object_id':
            return "<a href=/stix/{0}>{1}</href>".format(row.object_id.object_id, row.object_id.object_id)
        else:
            return super(SightingData, self).render_column(row, column)

class ObservableObjectData(BaseDatatableView):
    model = ObservableObject
    columns = ['id', 'type']
    order_columns = ['id', 'type']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'id':
            return "<a href=/observable/{0}>{0}</href>".format(row.id)
        elif column == 'type':
            t = row.type.name
            if row.type.model_name:
                m = apps.get_model(row._meta.app_label, row.type.model_name)
                o = m.objects.get(id=row.id)
                if hasattr(o, "name"):
                    return t + ":" + o.name
                elif hasattr(o, "value"):
                    return t + ":" + o.value
            return row.type.name
        else:
            return super(ObservableObjectData, self).render_column(row, column)

class IndicatorPatternData(BaseDatatableView):
    model = IndicatorPattern
    columns = ['pattern']
    order_columns = ['pattern']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'property':
            p = row.property.type.name + ":" + row.property.name
            return p
        else:
            return super(IndicatorPatternData, self).render_column(row, column)

class IndicatorData(BaseDatatableView):
    model = Indicator
    columns = ['created', 'name', 'pattern']
    order_columns = ['created', 'name', 'pattern']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'pattern':
            pattern = ""
            if row.pattern:
                pattern = row.pattern.pattern
            #pattern = " OR ".join(sorted(row.pattern.all().values_list("pattern", flat=True)))
            return "[" + pattern + "]"
        elif column == 'name':
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id.object_id,row.name)
        else:
            return super(IndicatorData, self).render_column(row, column)
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(pattern__pattern__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

