from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.db.models import Q

from ..models import *
from ..forms import *
import json
from dotmap import DotMap

def find_ref(ref, stix):
    if not "objects" in stix:
        return False
    for obj in stix["objects"]:
        if obj["id"] == ref:
            return obj
    return None

def stix2timeline(stix):
    if not "objects" in stix:
        return False
    groups = []
    items = []
    for obj in stix["objects"]:
        if obj["type"] == "sighting":
            sight = DotMap(obj)
            sor = sight.sighting_of_ref
            a = {}
            if sor.split("--")[0] == "threat-actor":
                actor = DotMap(find_ref(sor, stix))
                act = {
                    "id": actor.id,
                    "content": actor.name,
                }
                if not act in groups:
                    groups.append(act)
            wsr = sight.where_sighted_refs
            for w in wsr:
                if w.split("--")[0] == "identity":
                    tgt = DotMap(find_ref(w, stix))
                    item = {
                        "id": sight.id,
                        "content": tgt.name,
                        "group": act["id"],
                        "start": sight.first_seen,
                        #"end": sight.last_seen,
                        "className":sight.type,
                    }
                    if sight.last_seen:
                        item["end"] = sight.last_seen
                    if tgt.sectors:
                        item["subgroup"] = tgt.sectors[0]
                    #if tgt.sectors.all():
                    #    item["className"] = tgt.sectors.all()[0]
                    if not item in items:
                        items.append(item)
        elif obj["type"] == "report":
            report = DotMap(obj)
            start = report.published
            if not start:
                start = report.created
            item = {
                "id": report.id,
                "content": report.name,
                "group": None,
                "className": report.type,
                "start": start
            }
            for ref in report.object_refs:
                if ref.split("--")[0] == "threat-actor":
                    actor = DotMap(find_ref(ref, stix))
                    a = {
                        "id": actor.id,
                        "content": actor.name,
                    }
                    if not a in groups:
                        groups.append(a)
                    if not item["group"]:
                        item["group"] = a["id"]
            if not item in items:
                items.append(item)
    dataset = {
        "items":items,
        "groups":groups,
    }
    return dataset

def data_timeline(request=None, model=None, field=None):
    models = [
        "sighting",
        "report",
        "campaign",
        "intrusion_set",
    ]
    if model:
        models = [model]
    objects = STIXObject.objects.filter(
        object_type__name__in = models
    )

    groups = []
    items = []
    for obj in objects:
        if obj.object_type.name == "sighting":
            sight = get_obj_from_id(obj.object_id)
            sor = sight.sighting_of_ref
            a = {}
            if sor.object_id.split("--")[0] == "threat-actor":
                actor = get_obj_from_id(sor)
                act = {
                    "id": actor.object_id.object_id,
                    "content": actor.name,
                }
                if not act in groups:
                    groups.append(act)
            wsr = sight.where_sighted_refs.all()
            for w in wsr:
                if w.object_id.split("--")[0] == "identity":
                    tgt = get_obj_from_id(w)
                    item = {
                        "id": sight.object_id.object_id,
                        "content": tgt.name,
                        "group": act["id"],
                        "start": sight.first_seen.isoformat(),
                        #"end": sight.last_seen.isoformat(),
                    }
                    if sight.last_seen:
                        item["end"] = sight.last_seen.isoformat()
                    if tgt.labels.all():
                        item["subgroup"] = tgt.labels.all()[0]
                    if tgt.sectors.all():
                        item["className"] = tgt.sectors.all()[0]
                    if not item in items:
                        items.append(item)
        if obj.object_type.name == "report":
            report = get_obj_from_id(obj.object_id)
            start = report.published
            if not start:
                start = report.created
            item = {
                "id": report.object_id.object_id,
                "content": report.name,
                "group": None,
                "className": report.object_type.name,
                "start": start.isoformat()
            }
            for ref in report.object_refs.all():
                if ref.object_id.split("--")[0] == "threat-actor":
                    actor = get_obj_from_id(ref)
                    a = {
                        "id": actor.object_id.object_id,
                        "content": actor.name,
                    }
                    if not a in groups:
                        groups.append(a)
                    if not item["group"]:
                        item["group"] = a["id"]
            if not item in items:
                items.append(item)
    dataset = {
        "items":items,
        "groups":groups,
    }
    if not request:
        #print(dataset)
        return dataset
    return JsonResponse(dataset)

def viz_timeline(request, model=None, field=None):
    #if request.method == "POST":
    #    print(request.POST)
    data = data_timeline(model=model, field=field)
    form = TimelineForm()
    #print(form)
    c = {
        "form": form,
        "items": data["items"],
        "groups": data["groups"],
    }
    return render(request, "timeline_viz.html", c)

