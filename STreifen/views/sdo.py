from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages

import STreifen.models as mymodels
import STreifen.forms as myforms
from ..models import *
from ..forms import *
import json
import stix2

def stix2_json(request, id):
    obj = STIXObject.objects.get(object_id__object_id=id)
    objs = _get_related_obj(obj)
    bundle = stix_bundle(objs)
    j = json.dumps(json.loads(str(bundle)), indent=2)
    return HttpResponse(j,  content_type="application/json")

def _get_related_obj(sdo):
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
    if rels:
        ids += rels.values_list("object_id", flat=True)
        ids += rels.values_list("source_ref", flat=True)
        ids += rels.values_list("target_ref", flat=True)
    if sights:
        ids += sights.values_list("object_id", flat=True)
        ids += sights.values_list("sighting_of_ref", flat=True)
    oids = STIXObjectID.objects.filter(
        id__in=ids
    )
    for oid in oids:
        obj = myforms.get_obj_from_id(oid)
        if obj:
            objects.append(obj)
    return objects

def stix_bundle(objs):
    objects = ()
    """
    objs = _get_related_obj(sdo)
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
    if rels:
        ids += rels.values_list("object_id", flat=True)
        ids += rels.values_list("source_ref", flat=True)
        ids += rels.values_list("target_ref", flat=True)
    if sights:
        ids += sights.values_list("object_id", flat=True)
        ids += sights.values_list("sighting_of_ref", flat=True)
    oids = STIXObjectID.objects.filter(
        id__in=ids
    )
    for oid in oids:
        obj = myforms.get_obj_from_id(oid)
    """
    for obj in objs:
        if obj.object_type.name == 'identity':
            i = stix2.Identity(
                id=obj.object_id.object_id,
                name=obj.name,
                identity_class=obj.identity_class,
                description=obj.description,
                #sectors=[str(s.value) for s in obj.sectors.all()],
                sectors=[str(l.value) for l in obj.labels.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (i,)
        elif obj.object_type.name == 'attack-pattern':
            a = stix2.AttackPattern(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                created=obj.created,
                modified=obj.modified,
            )
            objects += (a,)
        elif obj.object_type.name == 'malware':
            m = stix2.Malware(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                labels=[str(l.value) for l in obj.labels.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (m,)
        elif obj.object_type.name == 'indicator':
            i = stix2.Indicator(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                labels=[str(l.value) for l in obj.labels.all()],
                pattern=[str(p.value) for p in obj.pattern.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (i,)
        elif obj.object_type.name == 'threat-actor':
            t = stix2.ThreatActor(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                labels=[str(l.value) for l in obj.labels.all()],
                aliases=[str(a.name) for a in obj.aliases.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (t,)
        elif obj.object_type.name == 'campaign':
            c = stix2.Campaign(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                #labels=[str(l.value) for l in obj.labels.all()],
                aliases=[str(a.name) for a in obj.aliases.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (c,)
        elif obj.object_type.name == 'relationship':
            r = stix2.Relationship(
                id=obj.object_id.object_id,
                relationship_type=obj.relationship_type.name,
                description=obj.description,
                source_ref=obj.source_ref.object_id,
                target_ref=obj.target_ref.object_id,
                created=obj.created,
                modified=obj.modified,
            )
            objects += (r,)
        elif obj.object_type.name == 'sighting':
            s = stix2.Sighting(
                id=obj.object_id.object_id,
                sighting_of_ref=obj.sighting_of_ref.object_id,
                where_sighted_refs=[str(w.object_id) for w in obj.where_sighted_refs.all()],
                first_seen=obj.first_seen,
                last_seen=obj.last_seen,
                created=obj.created,
                modified=obj.modified,
            )
            objects += (s,)
        elif obj.object_type.name == 'report':
            r = stix2.Report(
                id=obj.object_id.object_id,
                labels=[str(l.value) for l in obj.labels.all()],
                name=obj.name,
                description=obj.description,
                published=obj.published,
                object_refs=[str(r.object_id) for r in obj.object_refs.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (r,)
    bundle = stix2.Bundle(*objects)
    return bundle

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
                messages.add_message(
                    request, messages.SUCCESS, 'Created -> '+s.name,
                )
        elif "create_bulk" in request.POST:
            bulkform = InputForm(request.POST)
            input = None
            if bulkform.is_valid():
                input = bulkform.cleaned_data["input"]
            if input:
                if type == "indicator":
                    soform = SelectObservableForm(request.POST)
                    if soform.is_valid():
                        property = soform.cleaned_data["property"]
                        label = soform.cleaned_data["label"]
                        bulk_create_indicator(label,property,input)
                elif type == "malware":        
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 2:
                                m, created = Malware.objects.get_or_create(
                                    name=array[0],
                                )
                                l = MalwareLabel.objects.filter(value=array[1])
                                if l.count() == 1:
                                    m.labels.add(l[0])
                                    m.save()
    c = {
        "type": type,
        "form": form,
        "bulkform": bulkform,
    }
    if type == "report":
        c["bulkformat"] = "name,label,published,(description)"
    elif type == "threat-actor":
        c["bulkformat"] = "name,label,([alias,..])"
    elif type in ("identity", "malware"):
        c["bulkformat"] = "name,(label)"
    elif type == "indicator":
        c["soform"] = SelectObservableForm()
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

def get_model_from_id(id):
    type = ""
    for i in id.split("-")[0:2]:
        type += i.capitalize()
    m = getattr(mymodels, type)
    return m

def sdo_view(request, id):
    m = get_model_from_id(id)
    sdo = m.objects.get(object_id__object_id=id)
    form = getform(id.split("--")[0], instance=sdo)

    objs = _get_related_obj(sdo)
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
    tgt = STIXObject.objects.filter(object_type__in=drs.values("target"))
    if not sdo.object_type.name == "report":
      aoform.fields["objects"].choices = object_choices(
        ids=STIXObjectID.objects.filter(id__in=tgt)
      )
      aoform.fields["relation"].required = True

    if request.method == "POST":
        print(request.POST)
        if 'update' in request.POST:
            form = getform(id.split("--")[0],request=request,instance=sdo)
            if form.is_valid():
                s = form.save()
                if s.object_type.name == "threat-actor":
                    n = form.cleaned_data["new_alias"]
                    if n:
                        ta, created = ThreatActorAlias.objects.get_or_create(
                            name = n
                        )
                        s.aliases.add(ta)
                        s.save
                elif s.object_type.name == "campaign":
                    n = form.cleaned_data["new_alias"]
                    if n:
                        ta, created = CampaignAlias.objects.get_or_create(
                            name = n
                        )
                        s.aliases.add(ta)
                        s.save
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)
        elif 'detach' in request.POST:
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
                    print(obform)
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
        elif 'create_obj' in request.POST:
            sotid = request.POST.get('type')
            sot = STIXObjectType.objects.get(id=sotid)
            selected = sot.name
            soform.fields["type"].initial = sotid
            coform = getform(sot.name, request=request)
            if coform.is_valid():
                saved = coform.save()
                #report.object_refs.add(saved.object_id)
                report = add_object_refs(report, saved.object_id)
                report.save()
                redirect("/stix/"+id)

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
                redirect("/stix/"+id)

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
