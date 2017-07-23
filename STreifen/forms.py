from django import forms
from django.db.models import Q

from .models import *
import STreifen.models as mymodels

from operator import itemgetter

import logging
logging.basicConfig(level=logging.DEBUG)

class InputForm(forms.Form):
    input = forms.CharField(
        widget=forms.Textarea(
            attrs={'style':'height:400px;'}
        )
    )

class TimelineForm(forms.Form):
    models = [
        "report",
        "sighting",
        #"campaign",
        #"attack-pattern",
    ]
    objects = forms.ModelMultipleChoiceField(
        queryset=STIXObjectType.objects.filter(
            name__in=models
        ),
        widget=forms.CheckboxSelectMultiple(attrs={"checked":""})
    )
    def __init__(self, *args, **kwargs):
        super(TimelineForm, self).__init__(*args, **kwargs)
        self.fields["objects"].required = False

class RelationshipForm(forms.ModelForm):
    class Meta:
        model = Relationship
        fields = [
            "source_ref",
            "relationship_type",
            "target_ref",
            "description",
        ]

class CampaignForm(forms.ModelForm):
    new_alias = forms.CharField()
    class Meta:
        model = Campaign
        fields = [
            "name",
            "aliases",
            "first_seen",
            "last_seen",
            "description",
        ]
    def __init__(self, *args, **kwargs):
        super(CampaignForm, self).__init__(*args, **kwargs)
        self.fields["new_alias"].required = False

class SightingForm(forms.ModelForm):
    class Meta:
        model = Sighting
        fields = [
            "where_sighted_refs",
            "sighting_of_ref",
            "first_seen",
            "last_seen",
            "description",
        ]
    def __init__(self, *args, **kwargs):
        super(SightingForm, self).__init__(*args, **kwargs)
        self.fields["where_sighted_refs"].choices = object_choices(
            ids=STIXObjectID.objects.filter(
                object_id__startswith="identity--",
            ),
            dummy=True
        )

class ThreatActorForm(forms.ModelForm):
    new_alias = forms.CharField()
    class Meta:
        model = ThreatActor
        fields = [
            "name",
            "labels",
            "aliases",
            "description",
            "new_alias",
        ]
        #widgets = {
        #    "labels":forms.CheckboxSelectMultiple(),
        #}
    def __init__(self, *args, **kwargs):
        super(ThreatActorForm, self).__init__(*args, **kwargs)
        self.fields["new_alias"].required = False

class MalwareForm(forms.ModelForm):
    class Meta:
        model = Malware
        fields = [
            "name",
            "labels",
            "description",
        ]

class AttackPatternForm(forms.ModelForm):
    class Meta:
        model = AttackPattern
        fields = [
            "name",
            "description",
        ]

class IdentityForm(forms.ModelForm):
    new_label = forms.CharField()
    class Meta:
        model = Identity
        fields = [
            "name",
            "identity_class",
            "sectors",
            "labels",
            "description",
            "new_label",
        ]
    def __init__(self, *args, **kwargs):
        super(IdentityForm, self).__init__(*args, **kwargs)
        self.fields["identity_class"].initial = "organization"
        self.fields["new_label"].required = False


class DefinedRelationshipForm(forms.Form):
    relation = forms.ModelChoiceField(
        queryset=DefinedRelationship.objects.all()
    )

class SelectObjectForm(forms.Form):
    type = forms.ModelChoiceField(
        queryset=STIXObjectType.objects.filter(
            name__in=[
                "identity",
                "attack-pattern",
                "malware",
                "threat-actor",
                "relationship",
                "sighting",
                "indicator",
            ]
        ),
    )
    def __init__(self, *args, **kwargs):
        super(SelectObjectForm, self).__init__(*args, **kwargs)
        self.fields["type"].required = False


def get_related_obj(obj):
    rels = Relationship.objects.filter(
        Q(source_ref__object_id=obj.object_id)\
        |Q(target_ref__object_id=obj.object_id)\
    )
    #print(rels)
    sights = Sighting.objects.filter(
        Q(where_sighted_refs__object_id=obj.object_id)\
        |Q(sighting_of_ref__object_id=obj.object_id)\
    )
    objects = [obj]
    objdict = {}
    for rel in rels.all():
        o = None
        if rel.source_ref == obj.object_id:
            if not rel.target_ref.object_id in objdict:
                o = get_obj_from_id(rel.target_ref)
                objdict[rel.target_ref.object_id] = o
        elif rel.target_ref == obj.object_id:
            if not rel.source_ref.object_id in objdict:
                o = get_obj_from_id(rel.source_ref)
                objdict[rel.source_ref.object_id] = o
        if o:
            if not o in objects:
                objects.append(o)
    return rels, objects

def get_obj_from_id(soi):
    sot = soi.object_id.split('--')[0]
    m = ""
    for s in sot.split('-'):
        m += s.capitalize()
    obj = getattr(mymodels, m).objects.filter(object_id=soi)
    if obj.count() == 1:
        return obj.all()[0]
    else:
        logging.error("Object not found: "+soi.object_id)
    return None

def object_choices(ids=STIXObjectID.objects.all(), dummy=False):
    choices = []
    if dummy:
        choices = [("","----------")]
    for soi in ids:
        obj = get_obj_from_id(soi)
        name = ""
        if not obj:
            logging.error("Could not get object: "+soi.object_id)
            if soi.id:
                soi.delete()
        else:
            if obj.object_type.name == 'relationship':
                src = get_obj_from_id(obj.source_ref)
                tgt = get_obj_from_id(obj.target_ref)
                rel = obj.relationship_type.name
                if src and tgt and rel:
                    name = " ".join([src.name, rel, tgt.name])
            elif obj.object_type.name == 'sighting':
                sor = get_obj_from_id(obj.sighting_of_ref)
                tgt = []
                for wsr in obj.where_sighted_refs.all():
                    i = get_obj_from_id(wsr)
                    if i:
                        tgt.append(i.name)
                if sor and tgt:
                    name = ",".join(tgt) + " sighted " + sor.name
            else:
                if hasattr(obj, 'name'):
                    name = obj.name
            if name:
                choices.append((
                #choices += ((
                    obj.object_id.id,
                    obj.object_type.name + " : " + name,
                ))
    if choices:
        choices.sort(key=itemgetter(1))
    return choices

class AddObjectForm(forms.Form):
    relation = forms.ModelChoiceField(
        queryset=RelationshipType.objects.all()
    )
    objects = forms.ModelMultipleChoiceField(
        queryset=STIXObjectID.objects.all()
    )
    def __init__(self, *args, **kwargs):
        super(AddObjectForm, self).__init__(*args, **kwargs)
        self.fields["objects"].choices = object_choices()
        self.fields["relation"].required = False

class ReportLabelForm(forms.Form):
    label = forms.ModelMultipleChoiceField(
        queryset=ReportLabel.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={"checked":""})
    )

class ReportRefForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = [
            "object_refs",
        ]
        widgets = {
            "object_refs":forms.CheckboxSelectMultiple(),
        }

class ReportForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = [
            "name",
            "created_by_ref",
            "published",
            "labels",
            "description",
            "object_refs",
        ]
        widgets = {
            #"labels":forms.CheckboxSelectMultiple(),
            #"object_refs":forms.CheckboxSelectMultiple(),
        }
    def __init__(self, *args, **kwargs):
        super(ReportForm, self).__init__(*args, **kwargs)
        self.fields["created_by_ref"].choices = object_choices(
            ids=STIXObjectID.objects.filter(
                object_id__startswith="identity--",
            ),
            dummy=True
        )

class TypeSelectForm(forms.Form):
    types = forms.ModelMultipleChoiceField(
        queryset=STIXObjectType.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={"checked":""})
    )
    relation = forms.ModelMultipleChoiceField(
        queryset=RelationshipType.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={"checked":""})
    )
    def __init__(self, *args, **kwargs):
        super(TypeSelectForm, self).__init__(*args, **kwargs)
        self.fields["types"].required = False
        self.fields["relation"].required = False

class IndicatorForm(forms.ModelForm):
    class Meta:
        model = Indicator
        fields = [
            "name",
            "labels",
            "description",
            "valid_from",
            "valid_until",
            "pattern",
        ]

class PatternForm(forms.ModelForm):
    class Meta:
        model = IndicatorPattern
        fields = [
            "observable",
            "pattern",
        ]

class ObservablePropertyForm(forms.ModelForm):
    class Meta:
        model = ObservableProperty
        fields = [
            "key",
            "value",
        ]

class SelectObservableForm(forms.Form):
    label = forms.ModelChoiceField(
        queryset=IndicatorLabel.objects.all()
    )
    #property = forms.ModelChoiceField(
    #    queryset=ObservableObjectProperty.objects.all()
    #)
    indicates = forms.ModelChoiceField(
        queryset=Malware.objects.all()
    )
    def __init__(self, *args, **kwargs):
        super(SelectObservableForm, self).__init__(*args, **kwargs)
        self.fields["indicates"].required = False
