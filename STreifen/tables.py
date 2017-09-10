from django_datatables_view.base_datatable_view import BaseDatatableView
from django.apps import apps
from .models import *
from .forms import *

class ReportData(BaseDatatableView):
    model = Report
    columns = ['created', 'name', 'created_by_ref', 'published']
    order_columns = ['created', 'name', 'created_by_ref', 'published']
    max_display_length = 100

    def get_initial_queryset(self):
        qs = Report.objects.all()
        return qs
    def render_column(self, row, column):
        if column == 'id':
            return '<a onclick=ChangeRight({0}) class="btn btn-default btn-xs">{0}</button>'.format(row.id)
        elif column == 'publisher':
            p = Identity.objects.filter(object_id=row.created_by_ref)
            if p.count() == 1:
                return p[0].name
            else:
                return None
        elif column == 'name':
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id.object_id,row.name)
        elif column == 'object_refs':
            return row.object_refs.count()
        elif column == 'created_by_ref':
            name = ""
            if row.created_by_ref:
                c = get_obj_from_id(row.created_by_ref)
                name = c.name
            return name
        else:
            return super(ReportData, self).render_column(row, column)
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(published__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class CampaignData(BaseDatatableView):
    model = Campaign
    columns = ['created', 'name', 'aliases', 'first_seen']
    order_columns = ['created', 'name', 'aliases','first_seen']
    max_display_length = 100
    def render_column(self, row, column):
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
        else:
            return super(CampaignData, self).render_column(row, column)


class ThreatActorData(BaseDatatableView):
    model = ThreatActor
    columns = ['created', 'name', 'aliases']
    order_columns = ['created', 'name', 'aliases']
    max_display_length = 100
    def render_column(self, row, column):
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
        else:
            return super(ThreatActorData, self).render_column(row, column)
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(aliases__name__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class MalwareData(BaseDatatableView):
    model = Malware
    columns = ['created', 'name', 'labels']
    order_columns = ['created', 'name', 'labels']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'id':
            return '<a class="btn btn-default btn-xs">{0}</button>'.format(row.id)
        elif column == 'name':
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id.object_id,row.name)
        elif column == 'labels':
            l = []
            for label in row.labels.all():
                if not label.value in l:
                    l.append(label.value)
            return " / ".join(l)
        else:
            return super(MalwareData, self).render_column(row, column)
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(labels__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

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

class IdentityData(BaseDatatableView):
    model = Identity
    columns = ['created', 'name', 'sectors', 'labels']
    order_columns = ['created', 'name', 'sectors', 'labels']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'id':
            return '<a onclick=ChangeRight({0}) class="btn btn-default btn-xs">{0}</button>'.format(row.id)
        elif column == 'name':
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id.object_id,row.name)
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
            qs = qs.filter(labels__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()
