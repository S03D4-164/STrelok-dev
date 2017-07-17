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
    bundle = stix_bundle(obj)
    j = json.dumps(json.loads(str(bundle)), indent=2)
    return HttpResponse(j,  content_type="application/json")

def stix_bundle(sdo):
    objects = ()
    ids = [sdo.object_id.id]
    if sdo.object_type.name == "report":
        sdo = Report.objects.get(id=sdo.id)
        ids += sdo.object_refs.all().values_list("id",flat=True)
    rels = Relationship.objects.filter(
        Q(source_ref=sdo.object_id)\
        |Q(target_ref=sdo.object_id)\
    )
    ids += rels.values_list("object_id", flat=True)
    ids += rels.values_list("source_ref", flat=True)
    ids += rels.values_list("target_ref", flat=True)
    sights = Sighting.objects.filter(
        Q(where_sighted_refs=sdo.object_id)\
        |Q(sighting_of_ref=sdo.object_id)\
    )
    ids += sights.values_list("object_id", flat=True)
    ids += sights.values_list("sighting_of_ref", flat=True)
    oids = STIXObjectID.objects.filter(
        id__in=ids
    )
    for oid in oids:
        obj = myforms.get_obj_from_id(oid)
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

def sdo_list(request, type):
    sot = STIXObjectType.objects.get(name=type)
    form = getform(type)
    if request.method == "POST":
        form = getform(type, request=request)
        if form.is_valid():
            s = form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Created -> '+s.name,
            )
    c = {
        "type": type,
        "form": form,
    }
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

def sdo_view(request, id):
    type = ""
    for i in id.split("-")[0:2]:
        type += i.capitalize()
    m = getattr(mymodels, type)
    sdo = m.objects.get(object_id__object_id=id)
    stix = stix_bundle(sdo)
    rels, objects = get_related_obj(sdo)
    if sdo.object_type.name == "report":
        rels = Relationship.objects.filter(object_id__in=sdo.object_refs.all())
        for r in sdo.object_refs.all():
            o = get_obj_from_id(r)
            if not o.object_type.name == "relationship":
                if not o in objects:
                    objects.append(o)
    #print(stix)
    form = getform(id.split("--")[0], instance=sdo)
    #soform = SelectObjectForm()
    #selected = None
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
                form.save()
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
        elif 'select' in request.POST:
            sotid = request.POST.get('select')
            #print(sotid)
            if sotid:
                sot = STIXObjectType.objects.get(id=sotid)
                selected = sot.name
                soform.fields["type"].initial = sotid
                coform = _object_form(selected, report=report)
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
            coform = _object_form(sot.name, request=request, report=report)
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
        #"soform": soform,
        "aoform": aoform,
        #"selected": selected,
        #"coform": coform,
        #"rform": rform,
        "objects": objects,
        "rels": rels,
        #"sights": sightings,
        "stix":stix,
    }
    return render(request, 'base_view.html', c)
    #return render(request, 'report_view.html', c)
