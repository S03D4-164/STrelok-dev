from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.db.models import Q

from ..models import *
from ..forms import *
import json, hashlib
from dotmap import DotMap

def timeline_view(request, id=None):
    mask = True
    if request.user.is_authenticated():
        mask = False
    obj = None
    objs = []
    form = TimelineForm()
    if request.method == "POST":
        form = TimelineForm(request.POST)
        if form.is_valid():
            type = form.cleaned_data["group"]
            obj = STIXObject.objects.filter(object_type__in=type)
    if id:
        obj = STIXObject.objects.get(object_id__object_id=id)
        objs = get_related_obj(obj)
    else:
        if not obj:
            obj = STIXObject.objects.filter(object_type__name="threat-actor")
        for o in  obj:
            for r in get_related_obj(o):
                #objs.append(get_obj_from_id(o.object_id))
                objs.append(r)
        obj = None
    from .stix import stix_bundle
    stix = stix_bundle(objs, mask=mask)
    data = stix2timeline(json.loads(str(stix)))
    c = {
        "form": form,
        "obj":obj,
        "items": data["items"],
        "groups": data["groups"],
        "subgroups": data["subgroups"],
        "colors": data["colors"],
    }
    if mask == True:
        c["obj"] = obj.object_id
    return render(request, "timeline_viz.html", c)

def find_ref(ref, stix):
    if not "objects" in stix:
        return False
    for obj in stix["objects"]:
        if obj["id"] == ref:
            return obj
    return None

def set_group(so, data):
    sg = {
        "id": so.id,
        "content": "<a href=/stix/{0}>{1}</a>".format(so.id,so.name),
        "group": so.type
    }
    if not sg["id"] in data["subgroups"]:
        data["subgroups"][sg["id"]] = sg
    g = {
        "id": sg["group"],
        "content": sg["group"],
        "nested_groups":[]
    }
    if not g["id"] in data["groups"]:
        data["groups"][g["id"]] = g
    if not sg["id"] in data["groups"][g["id"]]["nested_groups"]:
        data["groups"][g["id"]]["nested_groups"].append(sg["id"])
    return data

def stix2timeline(stix):
    if not "objects" in stix:
        return None
    data = {
        "groups":{},
        "subgroups":{},
        "items":{},
        "colors":{},
    }
    for obj in stix["objects"]:
        if obj["type"] == "sighting":
            sighting = DotMap(obj)
            sor = sighting.sighting_of_ref
            if sor.split("--")[0] in [
                "threat-actor", "malware","attack-pattern"
            ]:
                so = find_ref(sor, stix)
                if so:
                    so = DotMap(so)
                    data = set_group(so, data)
                    wsr = sighting.where_sighted_refs
                    for w in wsr:
                        if w.split("--")[0] == "identity":
                            tgt = find_ref(w, stix)
                            if tgt:
                                tgt = DotMap(tgt)
                                item = {
                                    "id": sighting.id,
                                    #"content": tgt.name,
                                    "content": "<a class='box' href=/stix/{0}>{1}</a>".format(tgt.id,tgt.name),
                                    "group": so.id,
                                    "start": sighting.first_seen,
                                    "className":sighting.type,
                                    "subgroup": "",
                                    "end": "",
                                    "title": "",
                                }
                                if sighting.last_seen:
                                    item["end"] = sighting.last_seen
                                if tgt.sectors:
                                    item["subgroup"] = tgt.sectors[0]
                                    item["className"] = tgt.sectors[0]
                                item["title"] = "<div>"
                                item["title"] += " - ".join([item["start"],item["end"]])
                                item["title"] += "<br>subgroup: " + item["subgroup"]
                                item["title"] += "<br>className: " + item["className"]
                                item["title"] += "</div>"
                                if not item["id"] in data["items"]:
                                    data["items"][item["id"]] = item
                                    if not item["className"] in data["colors"]:
                                        cc = hashlib.md5(item["className"].encode("utf8")).hexdigest()[0:6]
                                        data["colors"][item["className"]] = "#" + str(cc)
        elif obj["type"] == "report":
            report = DotMap(obj)
            start = report.created
            if report.published:
                start= report.published
            item = {
                "id": report.id,
                "content": "<a href=/stix/{0}>{1}</a>".format(report.id,report.name),
                "group": None,
                "subgroup": report.type,
                "className": report.type,
                "start": start,
                "end":"",
                "title":"",
            }
            item["title"] = " - ".join([item["start"],item["end"]])
            for ref in report.object_refs:
                if ref.split("--")[0] == "threat-actor":
                    actor = find_ref(ref, stix)
                    if actor:
                        actor = DotMap(actor)
                        data = set_group(actor, data)
                        if not item["group"]:
                            item["group"] = actor.id
            if not item["id"] in data["items"]:
                data["items"][item["id"]] = item
                if not item["className"] in data["colors"]:
                    cc = hashlib.md5(item["className"].encode("utf8")).hexdigest()[0:6]
                    data["colors"][item["className"]] = "#" + str(cc)
        elif obj["type"] == "campaign":
            campaign = DotMap(obj)
            if campaign.first_seen:
                item = {
                    "id": campaign.id,
                    "content": "<a href=/stix/{0}>{1}</a>".format(campaign.id,campaign.name),
                    "group": None,
                    "start": campaign.first_seen,
                    "end":"",
                    "title":"",
                    "type":"background",
                }
                if campaign.last_seen:
                    item["end"] = campaign.last_seen
                for s in stix["objects"]:
                    if s["type"] == "relationship":
                        if s["relationship_type"] == "attributed-to" and s["source_ref"] == campaign.id:
                            t = find_ref(s["target_ref"], stix)
                            t = DotMap(t)
                            if t.type == "threat-actor":
                                data = set_group(t, data)
                                if not item["group"]:
                                    item["group"] = t.id
                if not item["group"]:
                    item["group"] = "campaign"
                    if not "campaign" in data["groups"]:
                        data["groups"]["campaign"] = {
                            "id":"campaign",
                            "content":"campaign",
                        }
                if not item["id"] in data["items"]:
                    data["items"][item["id"]] = item
                    #if not item["className"] in data["colors"]:
                    #    cc = hashlib.md5(item["className"].encode("utf8")).hexdigest()[0:6]
                    #    data["colors"][item["className"]] = "#" + str(cc)

    return data

"""
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
    data = data_timeline(model=model, field=field)
    #form = TimelineForm()
    c = {
        #"form": form,
        "items": data["items"],
        "groups": data["groups"],
    }
    return render(request, "timeline_viz.html", c)
"""
