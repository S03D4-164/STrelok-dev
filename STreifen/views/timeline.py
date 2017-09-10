from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.db.models import Q

from ..models import *
from ..forms import *
import json, hashlib
from dotmap import DotMap

def timeline_view(request, id=None):
    objs = []
    obj = None
    from .stix import stix_bundle
    if id:
        obj = STIXObject.objects.get(object_id__object_id=id)
        objs = get_related_obj(obj)
    else:
        for o in  STIXObject.objects.all():
            objs.append(get_obj_from_id(o.object_id))
    stix = stix_bundle(objs)
    data = stix2timeline(json.loads(str(stix)))
    c = {
        "form": TimelineForm(),
        "obj":obj,
        "items": data["items"],
        "groups": data["groups"],
        "subgroups": data["subgroups"],
        "colors": data["colors"],
    }
    return render(request, "timeline_viz.html", c)

def find_ref(ref, stix):
    if not "objects" in stix:
        return False
    for obj in stix["objects"]:
        if obj["id"] == ref:
            return obj
    return None

def stix2timeline(stix):
    if not "objects" in stix:
        return None
    groups = {}
    subgroups = {}
    items = {}
    color = {}
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
                    sg = {
                        "id": so.id,
                        "content": so.name,
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
                    wsr = sighting.where_sighted_refs
                    for w in wsr:
                        if w.split("--")[0] == "identity":
                            tgt = find_ref(w, stix)
                            if tgt:
                                tgt = DotMap(tgt)
                                item = {
                                    "id": sighting.id,
                                    "content": tgt.name,
                                    "group": sg["id"],
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
                "content": report.name,
                "group": None,
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
                        sg = {
                            "id": actor.id,
                            "content": actor.name,
                            "group":actor.type,
                        }
                        if not sg["id"] in data["subgroups"]:
                            data["subgroups"][sg["id"]] = sg
                        g = {
                            "id": sg["group"],
                            "content": sg["group"],
                            "nested_groups":[]
                        }
                        if not sg["group"] in data["groups"]:
                            data["groups"][sg["group"]] = g
                        if not sg["id"] in data["groups"][g["id"]]["nested_groups"]:
                            data["groups"][g["id"]]["nested_groups"].append(sg["id"])
                        if not item["group"]:
                            item["group"] = sg["id"]
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
                    "content": campaign.name,
                    "group": None,
                    "start": campaign.first_seen,
                    "end":"",
                    "title":"",
                    "className":campaign.type,
                }
                if campaign.last_seen:
                    item["end"] = campaign.last_seen
                for s in stix["objects"]:
                    if s["type"] == "relationship":
                        if s["relationship_type"] == "attributed-to" and s["source_ref"] == campaign.id:
                            t = find_ref(s["target_ref"], stix)
                            #if t:
                            t = DotMap(t)
                            if t.type == "threat-actor":
                                sg = {
                                    "id":t.id,
                                    "content":t.name,
                                    "group":t.type,
                                }
                                if not item["group"]:
                                    item["group"] = sg["id"]
                                if not sg["id"] in data["subgroups"]:
                                    data["subgroups"][sg["id"]] = sg
                                g = {
                                    "id":sg["group"],
                                    "content":sg["group"],
                                    "nested_groups":[],
                                }
                                if not sg["group"] in data["groups"]:
                                    data["groups"][g["id"]] = g
                                if not sg["id"] in data["groups"][g["id"]]["nested_groups"]:
                                    data["groups"][g["id"]]["nested_groups"].append(sg["id"])
                if not item["group"]:
                    item["group"] = "campaign"
                    if not "campaign" in data["groups"]:
                        data["groups"]["campaign"] = {
                            "id":"campaign",
                            "content":"campaign",
                        }
                if not item["id"] in data["items"]:
                    data["items"][item["id"]] = item
                    if not item["className"] in data["colors"]:
                        cc = hashlib.md5(item["className"].encode("utf8")).hexdigest()[0:6]
                        data["colors"][item["className"]] = "#" + str(cc)
    g = []
    for k,v in groups.items():
        g.append(v)
    dataset = {
        "items":items,
        "groups":g,
        "subgroups":subgroups,
        "color":color,
    }
    #return dataset
    return data

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

