from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.apps import apps

import STreifen.models as mymodels
import STreifen.forms as myforms
from ..models import *
from ..forms import *
from .stix import stix_bundle
from .chart import *

import json
import stix2

def get_related_obj(sdo):
    objects = []
    ids = [sdo.object_id.id]
    rels = None
    sights = None
    if sdo.object_type.name == "report":
        sdo = Report.objects.get(id=sdo.id)
        ids += sdo.object_refs.all().values_list("id",flat=True)
        rels = Relationship.objects.filter(id__in=sdo.object_refs.all())
        sights = Sighting.objects.filter(id__in=sdo.object_refs.all())
        
    else:
        rels = Relationship.objects.filter(
            Q(source_ref=sdo.object_id)\
            |Q(target_ref=sdo.object_id)\
        )
        sights = Sighting.objects.filter(
            Q(where_sighted_refs=sdo.object_id)\
            |Q(sighting_of_ref=sdo.object_id)\
        )
    rep = Report.objects.filter(object_refs=sdo.object_id)
    if rep:
        ids += rep.values_list("object_refs", flat=True)
    if rels:
        ids += rels.values_list("object_id", flat=True)
        ids += rels.values_list("source_ref", flat=True)
        ids += rels.values_list("target_ref", flat=True)
    if sights:
        ids += sights.values_list("object_id", flat=True)
        ids += sights.values_list("sighting_of_ref", flat=True)
        ids += sights.values_list("where_sighted_refs", flat=True)
    oids = STIXObjectID.objects.filter(
        id__in=ids
    )
    #print(oids)
    for oid in oids:
        obj = get_obj_from_id(oid)
        if obj:
            objects.append(obj)
    #print(objects)
    return objects

def bulk_create_indicator(label, property, input,   src=None):
    for line in input.split("\n"):
        if line:
            ip, created = IndicatorPattern.objects.get_or_create(
                property=property,
                value=line.strip()
            )
            i, created = Indicator.objects.get_or_create(
                name=line.strip()
            )
            i.pattern.add(ip)
            i.labels.add(label)
            i.save()
            if src.object_type.name == "report":
                src.object_refs.add(i.object_id)
    return

def sdo_list(request, type):
    sot = STIXObjectType.objects.get(name=type)
    form = getform(type)
    bulkform = InputForm()
    if request.method == "POST":
        if "create" in request.POST:
            form = getform(type, request=request)
            if form.is_valid():
                s = form.save()
                if s.object_type.name == "threat-actor":
                    alias = form.cleaned_data["new_alias"]
                    for n in s.name, alias:
                        if n:
                            ta, created = ThreatActorAlias.objects.get_or_create(
                                name = n
                            )
                            s.aliases.add(ta)
                            s.save
                elif s.object_type.name == "campaign":
                    alias = form.cleaned_data["new_alias"]
                    for n in s.name, alias:
                        if n:
                            ta, created = CampaignAlias.objects.get_or_create(
                                name = n
                            )
                            s.aliases.add(ta)
                            s.save
                elif s.object_type.name == "identity":
                    label = form.cleaned_data["new_label"]
                    if label:
                        l, created = IdentityLabel.objects.get_or_create(
                            value = label
                        )
                        s.labels.add(l)
                        s.save
                elif s.object_type.name == "indicator":
                    observable = form.cleaned_data["observable"]
                    if observable:
                        pattern = []
                        obs = []
                        for line in observable.split("\n"):
                            if line:
                                type = line.strip().split(":")[0]
                                value = ":".join(line.strip().split(":")[1:])
                                t = ObservableObjectType.objects.filter(name=type)
                                if t.count() == 1:
                                    t = t[0]
                                    print(t)
                                    if t.model_name:
                                        print(t.model_name)
                                        m = apps.get_model(t._meta.app_label, t.model_name)
                                        o = None
                                        if t.name == "file":
                                            o, cre = m.objects.get_or_create(
                                                type = t,
                                                name = value
                                            )
                                        else:
                                            o, cre = m.objects.get_or_create(
                                                type = t,
                                                value = value
                                            )
                                        if o and not o in obs:
                                            obs.append(o)
                                            pattern.append(type +"="+ value)
                        if pattern:
                            p, cre = IndicatorPattern.objects.get_or_create(
                                pattern = " OR ".join(sorted(pattern))
                            )
                            if cre:
                                p.observable.add(*obs)
                                p.save()
                            if p:
                                s.pattern.add(p)
                                s.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Created -> '+s.name,
                )
        elif "create_bulk" in request.POST:
            bulkform = InputForm(request.POST)
            input = None
            if bulkform.is_valid():
                input = bulkform.cleaned_data["input"]
            if input:
                if type == "threat-actor":
                    label = None
                    sform = ThreatActorLabelForm(request.POST)
                    if sform.is_valid():
                        label = sform.cleaned_data["labels"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                t, cre = ThreatActor.objects.get_or_create(name=array[0])
                                ta, cre = ThreatActorAlias.objects.get_or_create(name=array[0])
                                t.aliases.add(ta)
                                for l in label:
                                    t.labels.add(l)
                                if len(array) >= 2:
                                    for a in array[1:]:
                                        ta, cre = ThreatActorAlias.objects.get_or_create(name=a)
                                        t.aliases.add(ta)
                                t.save()
                elif type == "indicator":
                    sform = SelectObservableForm(request.POST)
                    if sform.is_valid():
                        property = sform.cleaned_data["property"]
                        label = sform.cleaned_data["label"]
                        bulk_create_indicator(label,property,input)
                elif type == "identity":
                    ic = None
                    sform = IdentityClassForm(request.POST)
                    if sform.is_valid():
                        ic = sform.cleaned_data["identity_class"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                i, cre = Identity.objects.get_or_create(
                                    name = array[0],
                                    identity_class = ic,
                                )
                                if len(array) >= 2:
                                    il, cre = IdentityLabel.objects.get_or_create(
                                        value = array[1],
                                    )
                                    i.labels.add(il)
                                if len(array) >= 3:
                                    i.description = array[2]
                                i.save()
                elif type == "malware":
                    label = None
                    sform = MalwareLabelForm(request.POST)
                    if sform.is_valid():
                        label = sform.cleaned_data["labels"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                m, created = Malware.objects.get_or_create(
                                    name=array[0],
                                )
                                for l in label:
                                    m.labels.add(l)
                                if len(array) >= 2:
                                    m.description = array[1]
                                m.save()
    c = {
        "type": type,
        "form": form,
        "bulkform": bulkform,
    }
    if type == "report":
        c["bulkformat"] = "name,label,published,(description)"
    elif type == "threat-actor":
        c["bulkformat"] = "name,([alias,..])"
        c["sform"] = ThreatActorLabelForm()
        c["data"] = stats_ati()
    elif type == "malware":
        c["bulkformat"] = "name,(description)"
        c["sform"] = MalwareLabelForm()
    elif type == "identity":
        c["bulkformat"] = "name,(label,description)"
        c["sform"] = IdentityClassForm()
    elif type == "indicator":
        c["sform"] = SelectObservableForm()
    return render(request, 'base_list.html', c)

def getform(type, request=None, instance=None, report=False):
    post = None
    if request:
        if request.method == 'POST':
            post = request.POST
    if type == "identity":
        return IdentityForm(post,instance=instance)
    elif type == "attack-pattern":
        return AttackPatternForm(post,instance=instance)
    elif type == "report":
        return ReportForm(post,instance=instance)
    elif type == "malware":
        return MalwareForm(post,instance=instance)
    elif type == "threat-actor":
        return ThreatActorForm(post,instance=instance)
    elif type == "indicator":
        return IndicatorForm(post,instance=instance)
    elif type == "campaign":
        return CampaignForm(post,instance=instance)
    elif type == "relationship":
        form = RelationshipForm(post,instance=instance)
        if report:
            choices = myforms.object_choices(
                ids=report.object_refs.all().exclude(
                    object_id__startswith = 'relationship'
                ).exclude(
                    object_id__startswith = 'sighting'
                )
            )
            form.fields["source_ref"].choices = choices
            form.fields["target_ref"].choices = choices
        return form
    elif type == "sighting":
        form = SightingForm(post,instance=instance)
        if report:
            wsr = myforms.object_choices(
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
    return False

def add_object_refs(report, oid):
    report.object_refs.add(oid)
    if oid.object_id.split("--")[0] == 'relationship':
        r = get_obj_from_id(oid)
        report.object_refs.add(r.source_ref)
        report.object_refs.add(r.target_ref)
    elif oid.object_id.split("--")[0] == 'sighing':
        r = get_obj_from_id(oid)
        report.object_refs.add(r.sighting_of_ref)
        for wsr in r.where_sighted_of_refs.all():
            report.object_refs.add(wsr)
    return report

def get_model_from_type(type):
    name = ""
    for i in type.split("-")[0:2]:
        name += i.capitalize()
    m = getattr(mymodels, name)
    return m

def sdo_view(request, id):
    m = get_model_from_type(id)
    sdo = m.objects.get(object_id__object_id=id)
    form = getform(id.split("--")[0], instance=sdo)

    objs = get_related_obj(sdo)
    stix = stix_bundle(objs)
    rels = []
    sights = []
    objects = []
    for o in objs:
        if o.object_type.name == "relationship":
            rels.append(o)
        elif o.object_type.name == "sighting":
            sights.append(o)
        else:
            objects.append(o)
    """
    rels, objects = get_related_obj(sdo)
    if sdo.object_type.name == "report":
        rels = Relationship.objects.filter(object_id__in=sdo.object_refs.all())
        for r in sdo.object_refs.all():
            o = get_obj_from_id(r)
            if not o.object_type.name == "relationship":
                if not o in objects:
                    objects.append(o)
    """

    soform = SelectObjectForm()
    selected = None
    coform = None

    aoform = AddObjectForm()
    # Get defined relationship from source
    drs = DefinedRelationship.objects.filter(
        source=sdo.object_type
    )
    aoform.fields["relation"].queryset = RelationshipType.objects.filter(
      id__in=drs.values("type")
    )
    #tgt = STIXObject.objects.filter(object_type__in=drs.values("target"))
    if not sdo.object_type.name == "report":
      aoform.fields["objects"].choices = object_choices(
        #ids=STIXObjectID.objects.filter(id__in=tgt)
        ids=[]
      )
      aoform.fields["relation"].required = True
    elif sdo.object_type.name == "report":
      aoform.fields["objects"].choices = object_choices(
        ids=STIXObjectID.objects.all()
      )
    if sdo.object_type.name == "identity":
        aoform = SightingForm()

    if request.method == "POST":
        #print(request.POST)
        if 'update' in request.POST:
            form = getform(id.split("--")[0],request=request,instance=sdo)
            if form.is_valid():
                s = form.save()
                if s.object_type.name == "threat-actor":
                    n = form.cleaned_data["new_alias"]
                    if n:
                        ta, cre = ThreatActorAlias.objects.get_or_create(
                            name = n
                        )
                        s.aliases.add(ta)
                        s.save()
                elif s.object_type.name == "identity":
                    l = form.cleaned_data["new_label"]
                    if l:
                        il, cre = IdentityLabel.objects.get_or_create(
                            value = l
                        )
                        s.labels.add(il)
                        s.save()
                elif s.object_type.name == "campaign":
                    n = form.cleaned_data["new_alias"]
                    if n:
                        ta, cre = CampaignAlias.objects.get_or_create(
                            name = n
                        )
                        s.aliases.add(ta)
                        s.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)
        elif 'detach[]' in request.POST:
            dlist = request.POST.getlist("detach[]")
            for i in STIXObjectID.objects.filter(
                object_id__in=dlist
            ):
                d = get_obj_from_id(i)
                d.delete()
            messages.add_message(
                request, messages.SUCCESS, 'Removed.'
            )
            #return redirect("/stix/"+id)
        elif 'detach_ref' in request.POST:
            rform = ReportRefForm(request.POST, instance=report)
            #print(rform)
            if rform.is_valid():
                rform.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)
        elif 'delete' in request.POST:
            name = sdo.name
            sdo.delete()
            messages.add_message(
                request, messages.SUCCESS,
                'Deleted -> ' + name
            )
            return redirect("/stix/"+id.split("--")[0])
        elif 'create_bulk' in request.POST:
            bform = InputForm(request.POST)
            input = None
            if bform.is_valid():
                input =  bform.cleaned_data["input"]
            soform = SelectObjectForm(request.POST)
            if soform.is_valid():
                t = soform.cleaned_data["type"]
                if t.name == "indicator":
                    obform = SelectObservableForm(request.POST)
                    #print(obform)
                    if obform.is_valid():
                        property = obform.cleaned_data["property"]
                        label = obform.cleaned_data["label"]
                        bulk_create_indicator(label,property,input,src=sdo)
        elif 'select' in request.POST:
            sotid = request.POST.get('select')
            #print(sotid)
            if sotid:
                sot = STIXObjectType.objects.get(id=sotid)
                selected = sot.name
                soform.fields["type"].initial = sotid
                #coform = _object_form(selected, report=report)
                coform = getform(selected)
                aoform.fields["objects"].choices = object_choices(
                    ids=STIXObjectID.objects.filter(
                        object_id__startswith=selected.split("--")[0]
                    )
                )
        elif 'select_rel' in request.POST:
            rt = request.POST.get('select_rel')
            if rt:
                #r = RelationshipType.objects.get(id=rid)
                drs = DefinedRelationship.objects.filter(
                    source=sdo.object_type,
                    type__id=rt,
                )
                t = STIXObjectType.objects.filter(id__in=drs.values_list("target", flat=True))
                so = STIXObject.objects.filter(
                    object_type__in=t,
                )
                #print(so)
                aoform.fields["objects"].choices = object_choices(
                    ids=STIXObjectID.objects.filter(
                        id__in=so.values_list("object_id__id",flat=True)
                    )
                )
        elif 'create_obj' in request.POST:
            sotid = request.POST.get('type')
            sot = STIXObjectType.objects.get(id=sotid)
            selected = sot.name
            soform.fields["type"].initial = sotid
            coform = getform(sot.name, request=request)
            if coform.is_valid():
                saved = coform.save()
                #report.object_refs.add(saved.object_id)
                report = add_object_refs(sdo, saved.object_id)
                report.save()
                return redirect("/stix/"+id)

        elif 'add_sight' in request.POST:
            aoform = SightingForm(request.POST)
            if aoform.is_valid():
                refs = aoform.cleaned_data["sighting_of"]
                first_seen = aoform.cleaned_data["first_seen"]
                last_seen = aoform.cleaned_data["last_seen"]
                description = aoform.cleaned_data["description"]
                for ref in refs:
                    s = Sighting.objects.create(
                        sighting_of_ref=ref,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        description=description,
                    )
                    s.where_sighted_refs.add(sdo.object_id)
                    s.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)
        elif 'add_obj' in request.POST:
            aoform = AddObjectForm(request.POST)
            if aoform.is_valid():
                refs = aoform.cleaned_data["objects"]
                rel = aoform.cleaned_data["relation"]
                for ref in refs:
                    if sdo.object_type.name == "report":
                        sdo.object_refs.add(ref)
                    else:
                        Relationship.objects.get_or_create(
                            source_ref=sdo.object_id,
                            relationship_type=rel,
                            target_ref=ref,
                        )
                #report.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)

    c = {
        "obj": sdo,
        "form": form,
        "soform": soform,
        "aoform": aoform,
        "bform": InputForm(),
        #"selected": selected,
        "coform": coform,
        #"rform": rform,
        "objects": objects,
        "rels": rels,
        "sights": sights,
        "stix":stix,
    }
    if selected == "indicator":
        c["obform"] = ObservablePropertyForm()
    return render(request, 'base_view.html', c)
    #return render(request, 'report_view.html', c)
