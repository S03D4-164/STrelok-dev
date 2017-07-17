from django_datatables_view.base_datatable_view import BaseDatatableView
from .models import *

class ReportData(BaseDatatableView):
    model = Report
    columns = ['created', 'name', 'published']
    order_columns = ['created', 'name', 'published']
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
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id,row.name)
        else:
            return super(ReportData, self).render_column(row, column)
    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            qs = qs.filter(published__value__iregex=search) \
                | qs.filter(name__iregex=search)
        return qs.distinct()

class ThreatActorData(BaseDatatableView):
    model = ThreatActor
    columns = ['created', 'name', 'aliases']
    order_columns = ['created', 'name', 'aliases']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'id':
            return '<a class="btn btn-default btn-xs">{0}</button>'.format(row.id)
        elif column == 'name':
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id,row.name)
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
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id,row.name)
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

class IndicatorData(BaseDatatableView):
    model = Indicator
    columns = ['created', 'name', 'pattern']
    order_columns = ['created', 'name', 'pattern']
    max_display_length = 100
    def render_column(self, row, column):
        if column == 'pattern':
            pattern = ""
            for p in row.pattern.all():
                pattern += p.value + "<br>"
            return pattern
        elif column == 'name':
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id,row.name)
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
            return '<a href="/stix/{0}">{1}</a>'.format(row.object_id,row.name)
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
