from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.apps import apps

from ..models import *
from ..forms import *
from .stix import stix_bundle
from .chart import *

import json
import stix2

from django_otp.decorators import otp_required

def get_obs(o):
    t = o.type
    if t.model_name:
        m = apps.get_model(t._meta.app_label, t.model_name)
        obs = m.objects.get(id=o.id)
        return obs
    return None

def obs_view(request, id):
    o = ObservableObject.objects.get(id=id)
    dict = {id:{}}
    if o.type.model_name:
        m = apps.get_model(o._meta.app_label, o.type.model_name)
        o = m.objects.get(id=o.id)
        s = None
        refs = []
        if o.type.name == "domain-name":
            for r in o.resolves_to_refs.all():
                m = apps.get_model(r._meta.app_label, r.type.model_name)
                ref = m.objects.get(id=r.id)
                if ref.type.name == "ipv4-addr":
                    i = stix2.IPv4Address(value=ref.value)
                    dict[ref.id] = json.loads(str(i))
                    refs.append(str(ref.id))
            s = stix2.DomainName(
                value=o.value,
                #resolves_to_refs=refs,
            )
            #dict[id] = json.loads(str(s))
            #dict[id]["resolves_to_refs"] = refs
        elif o.type.name == "file":
            s = stix2.File(name=o.name,)
            #dict[id] = json.loads(str(s))
        elif o.type.name == "ipv4-addr":
            s = stix2.IPv4Address(value=o.value,)
        elif o.type.name == "url":
            s = stix2.URL(value=o.value,)
        if s:
            dict[id] = json.loads(str(s))
            if refs:
                dict[id]["resolves_to_refs"] = refs
    #form = getform(o.type.name,instance=o)
    form = getobsform(o.type.name,instance=o)
    if request.POST:
        #print(request.POST)
        if "update" in request.POST:
            #form = getform(o.type.name,instance=o, request=request)
            form = getobsform(o.type.name,instance=o, request=request)
            if form.is_valid():
                s = form.save()
                if o.type.name in ["domain-name"]:
                    new = form.cleaned_data["new_refs"]
                    for line in new.split("\n"):
                        if line:
                            #o, p = create_obs_from_line(line)
                            o = create_obs_from_line(line)
                            s.resolve_to_refs.add(o)
                            #if not p in pattern:
                            #    pattern.append(p)
                s.save()
                
    objects = []
    rels = []
    sights = []
    observables = []
    value=None
    if hasattr(o, "value"):
        value = o.value
    elif hasattr(o, "name"):
        value = o.name
    ods = ObservedData.objects.filter(observable_objects=o)
    for od in ods:
        for s in Sighting.objects.filter(observed_data_refs=od):

            for ro in get_related_obj(s):
                if ro.object_type.name == "sighting":
                    if not ro in sights:
                        sights.append(ro)
                elif ro.object_type.name == "relationship":
                    if not ro in rels:
                        rels.append(ro)
                else:
                    if not ro in objects:
                        objects.append(ro)
    ind = Indicator.objects.filter(pattern__pattern__icontains=value)
    for i in ind:
        if not i in objects:
            objects.append(i)
            rs = Relationship.objects.filter(
                source_ref=i.object_id,
                relationship_type=RelationshipType.objects.get(name="indicates")
            )
            for r in rs:
                if not r in rels:
                    rels.append(r)
            for tgt in rel.values_list("target_ref", flat=True):
                t = get_obj_from_id(tgt)
                if not t in objects:
                    objects.append(t)
    c = {
        "obj":o,
        "type":o.type.name,
        "form":form,
        "stix":json.dumps(dict, indent=2),
        "objects":objects,
        "rels":rels,
        "sights":sights,
    }
    return render(request, 'base_view.html', c)

def create_obs(type, value):
    t = ObservableObjectType.objects.filter(name=type)
    if t.count() == 1:
        t = t[0]
        if t.model_name:
            m = apps.get_model(t._meta.app_label, t.model_name)
            if t.name == "file":
                o, cre = m.objects.get_or_create(
                    type = t,
                    name = value
                )
                #pattern = type + ":name="+ value
            else:
                o, cre = m.objects.get_or_create(
                    type = t,
                    value = value
                )
                #pattern = type + ":value=" + value
    #return o, pattern
    return o

def create_obs_from_line(line):
    o = None
    pattern = None
    type = line.strip().split(":")[0]
    value = ":".join(line.strip().split(":")[1:]).strip()
    o  = create_obs(type, value)
    """
    o, pattern = create_obs(type, value)
    t = ObservableObjectType.objects.filter(name=type)
    if t.count() == 1:
        t = t[0]
        if t.model_name:
            m = apps.get_model(t._meta.app_label, t.model_name)
            if t.name == "file":
                o, cre = m.objects.get_or_create(
                    type = t,
                    name = value
                )
                pattern = type + ":name="+ value
            else:
                o, cre = m.objects.get_or_create(
                    type = t,
                    value = value
                )
                pattern = type + ":value=" + value
    return o, pattern
    """
    return o

def obs2pattern(observable, new=None, indicator=None, generate=False):
    pattern = []
    obs = []
    if observable:
        for o in observable:
            obs.append(o.id)
            o = get_obs(o)
            p = o.type.name
            if hasattr(o,"name"):
                p += ":name=" + o.name
            elif hasattr(o,"value"):
                p += ":value=" + o.value
            pattern.append(p)
    for line in new.split("\n"):
        if line:
            #o, p = create_obs_from_line(line)
            o = create_obs_from_line(line)
            if o:
                obs.append(o.id)
                p = o.type + ":"
                if o.type == "file":
                    p += o.name
                else:
                    p += o.value
                pattern.append(p)
    p = None
    if pattern:
        if indicator:
            p = indicator.pattern
            if p:
                p.observable.clear()
                p.observable.add(*obs)
                if generate:
                    p.pattern = "[" + " OR ".join(sorted(pattern)) + "]"
                    #print(p.pattern)
                p.save()
            else: 
                p = IndicatorPattern.objects.create(
                    pattern = "[" + " OR ".join(sorted(pattern)) + "]"
                )
                p.observable.add(*obs)
                p.save()
                indicator.pattern = p
                indicator.save()
        else:
            p = IndicatorPattern.objects.create(
                pattern = " OR ".join(sorted(pattern))
            )
            p.observable.add(*obs)
            p.save()
    return p

#def getform(type, request=None, instance=None, report=None):
def getobsform(type, request=None, instance=None, report=None):
    post = None
    if request:
        if request.method == 'POST':
            post = request.POST
    if type == "domain-name":
        return DomainNameForm(post,instance=instance)
    else:
        return DomainNameForm(post,instance=instance)
    """
    elif type == "attack-pattern":
        return AttackPatternForm(post,instance=instance)
    elif type == "campaign":
        return CampaignForm(post,instance=instance)
    elif type == "course-of-action":
        return CourseOfActionForm(post,instance=instance)
    elif type == "identity":
        return IdentityForm(post,instance=instance)
    elif type == "intrusion-set":
        return IntrusionSetForm(post,instance=instance)
    elif type == "malware":
        return MalwareForm(post,instance=instance)
    elif type == "observed-data":
        return ObservedDataForm(post,instance=instance)
    elif type == "report":
        return ReportForm(post,instance=instance)
    elif type == "threat-actor":
        return ThreatActorForm(post,instance=instance)
    elif type == "tool":
        return ToolForm(post,instance=instance)
    elif type == "vulnerability":
        return VulnerabilityForm(post,instance=instance)
    elif type == "indicator":
        return IndicatorForm(post,instance=instance)
    elif type == "relationship":
        form = RelationshipForm(post,instance=instance)
        if report:
            # exclude SRO
            choices = object_choices(
                ids=report.object_refs.all().exclude(
                Q(object_id__startswith="relationship--")|\
                Q(object_id__startswith="sighting--")|\
                Q(object_id__startswith="observed-data--")|\
                Q(object_id__startswith="report--")
                )
            )
            form.fields["source_ref"].choices = choices
            form.fields["target_ref"].choices = choices
        return form
    elif type == "sighting":
        form = SightingForm(post,instance=instance)
        if report:
            wsr = object_choices(
                ids=report.object_refs.filter(
                    object_id__startswith="identity"
                )
            )
            form.fields["where_sighted_refs"].choices = wsr
            sor = myforms.object_choices(
                ids=report.object_refs.all().exclude(
                    object_id__startswith="relationship"
                ).exclude(
                    object_id__startswith="sighting"
                )
            )
            form.fields["sighting_of_ref"].choices = sor
        return form
    """
    return None

def _get_model_from_type(type):
    name = ""
    t = type.split("--")[0]
    for i in t.split("-"):
        name += i.capitalize()
    m = getattr(mymodels, name)
    return m

