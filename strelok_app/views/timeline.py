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
        if obj.object_type.name == "identity" and mask == True:
            obj = obj.object_id.object_id
        else:
            obj = obj
    else:
        if obj:
            for o in  obj:
                for r in get_related_obj(o):
                    objs.append(r)
        else:
            obj = STIXObject.objects.all()
            """
            obj = STIXObject.objects.filter(
                object_type__name__in=[
                    "threat-actor"
                ])
            """
            for o in  obj:
                objs.append(get_obj_from_id(o.object_id))
        obj = None
    from .stix import stix_bundle
    stix = stix_bundle(objs, mask=mask)
    #print(stix)
    data = stix2timeline(json.loads(str(stix)))
    #print(data)
    c = {
        "form": form,
        "id":id,
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

def find_attr(ref, stix):
    if not "objects" in stix:
        return False
    for obj in stix["objects"]:
        if obj["type"] == "relationship":
            if obj["relationship_type"] == "attributed-to":
                if obj["source_ref"] == ref:
                    return find_ref(obj["target_ref"], stix)
    return None


def set_group(so, data):
    # add object to subgroup and object_type to group
    sg = {
        "id": so.id,
        "content": "<a href=/stix/{0}>{1}</a>".format(
            so.id,so.name
        ),
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

def set_item(item, data):
    item["title"] = "<div>"
    item["title"] += " - ".join([item["start"],item["end"]])
    item["title"] += "<br>subgroup: " + item["subgroup"]
    item["title"] += "<br>className: " + item["className"]
    item["title"] += "</div>"
    if item["group"] and not item["id"] in data["items"]:
        data["items"][item["id"]] = item
        if item["className"] and not item["className"] in data["colors"]:
            cc = hashlib.md5(item["className"].encode("utf8")).hexdigest()[0:6]
            data["colors"][item["className"]] = "#" + str(cc)
    return data

def stix2timeline(stix):
    data = {
        "groups":{},
        "subgroups":{},
        "items":{},
        "colors":{},
    }
    if not "objects" in stix:
        return data
    # map objects have timestamp
    for obj in stix["objects"]:
        if obj["type"] == "sighting":
            sighting = DotMap(obj)
            sor = sighting.sighting_of_ref
            if sor.split("--")[0] in [
                "attack-pattern",
                "campaign",
                "malware",
                "tool",
                #"threat-actor",
            ]:
                so = find_ref(sor, stix)
                if so:
                    so = DotMap(so)
                    a = find_attr(sor, stix)
                    if a:
                        a = DotMap(a)
                        data = set_group(a, data)
                    #elif not so.type == "campaign":
                    else:
                        data = set_group(so, data)
                    wsr = sighting.where_sighted_refs
                    for w in wsr:
                        if w.split("--")[0] == "identity":
                            tgt = find_ref(w, stix)
                            if tgt:
                                tgt = DotMap(tgt)
                                item = {
                                    "id": sighting.id,
                                    "content": "<a class='box' href=/stix/{0}>{1}</a>".format(
                                        tgt.id,tgt.name
                                    ),
                                    "group": so.id,
                                    #"group": None,
                                    "subgroup": sighting.type,
                                    "className":sighting.type,
                                    "start": sighting.first_seen,
                                    "end": "",
                                    "title": "",
                                }
                                if a:
                                    item["group"] = a.id
                                if sighting.last_seen:
                                    item["end"] = sighting.last_seen
                                if tgt.sectors:
                                    item["subgroup"] = tgt.sectors[0]
                                    item["className"] = tgt.sectors[0]
                                #print(item)
                                data = set_item(item, data)
        elif obj["type"] == "report":
            report = DotMap(obj)
            start = report.created
            if report.published:
                start= report.published
            item = {
                "id": report.id,
                "content": "<a class='box' href=/stix/{0}>{1}</a>".format(
                    report.id,report.name
                ),
                "group": None,
                "subgroup": report.type,
                "className": report.type,
                "start": start,
                "end":"",
                "title":"",
            }
            for ref in report.object_refs:
                if ref.split("--")[0] == "threat-actor":
                    actor = find_ref(ref, stix)
                    if actor:
                        actor = DotMap(actor)
                        data = set_group(actor, data)
                        if not item["group"]:
                            item["group"] = actor.id
                #if ref.split("--")[0] == "campaign":
            data = set_item(item, data)
        elif obj["type"] == "campaign":
            campaign = DotMap(obj)
            if campaign.first_seen:
                # if type is background, subgroup and className must be empty
                item = {
                    "id": campaign.id,
                    "content": "<a href=/stix/{0}>{1}</a>".format(
                        campaign.id,campaign.name
                    ),
                    #"group": None,
                    "group": campaign.id,
                    "subgroup": "",
                    "className": "",
                    "start": campaign.first_seen,
                    "end": campaign.first_seen,
                    "title":"",
                    "type":"background",
                }
                if campaign.last_seen:
                    item["end"] = campaign.last_seen
                a = find_attr(campaign.id, stix)
                if a:
                    a = DotMap(a)
                    data = set_group(a, data)
                    item["group"] = a.id
                data = set_item(item, data)

    return data

