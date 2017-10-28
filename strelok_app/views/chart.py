from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.db.models import Q

from ..models import *
from ..forms import *
from collections import OrderedDict
import json, hashlib

def actor_chart(request, cnt_by='sector'):
    sights = Sighting.objects.all()
    #tgt = Identity.objects.all()
    tgt = Identity.objects.filter(object_id__in=sights.values("where_sighted_refs"))
    rels = Relationship.objects.all()
    data = cnt_actor_from_tgt(tgt, rels, sights)
    dataset = []
    for d in data:
        target = None
        if d["name"] == "Unknown":
            target = tgt.filter(id__in=d["id"])
        dd = cnt_tgt_by_prop(
            cnt_by=cnt_by,
            actor_name=d["name"],
            tgt=target,
            drilldown=False,
        )
        drilldown = {
            "name": "Targets of " + d["name"],
            "data": json.loads(dd),
        }
        da = {
            "name":d["name"],
            "y":d["y"],
            "drilldown":drilldown,
        }
        dataset.append(da)
    dataset = json.dumps(dataset,indent=2)
    return HttpResponse(dataset,  content_type="application/json")

def cnt_actor_from_tgt(tgt, rels, sights):
    data = {}
    for a in ThreatActor.objects.all():
        data[a.name] = 0
    unidentified = []
    unknown = len(tgt)
    for t in tgt:
        l = []
        s = sights.filter(
            where_sighted_refs__object_id=t.object_id
        )
        l += s.values_list("sighting_of_ref",flat=True)
        r = rels.filter(
            target_ref=t.object_id
        )
        l += r.values_list("source_ref",flat=True)
        if l:
            at = Relationship.objects.filter(
                source_ref__in=list(set(l)),
                relationship_type__name="attributed-to",
                target_ref__object_id__startswith="threat-actor",
            )
            l += at.values_list("target_ref",flat=True)
            ta = ThreatActor.objects.filter(object_id__in=list(set(l)))
            if ta:
                for a in ta:
                    data[a.name] += 1
            else:
                unidentified.append(t.id)
        else:
            unknown -= 1
    dd = []
    for k, v in data.items():
        if v:
            ai = {
                "name": k,
                "y": v,
            }
            dd.append(ai)
            unknown -= v
    dd = sorted(
        dd,
        key=lambda kv: kv["y"],
        reverse=True
    )
    if unknown:
        dd.append({
            "name":"Unknown",
            "y":unknown,
            "id":unidentified,
        })
    return dd

def target_chart(request, cnt_by="sector"):
    data = cnt_tgt_by_prop(cnt_by=cnt_by)
    return HttpResponse(data,  content_type="application/json")

def cnt_tgt_by_prop(cnt_by="sector", actor_name=None, drilldown=True, tgt=None):
    dataset = []
    sights = Sighting.objects.filter(
        where_sighted_refs__object_id__object_id__startswith="identity--",
        #sighting_of_ref__object_id__startswith="threat-actor--",
    )
    rels = Relationship.objects.filter(
        #source_ref__object_id__startswith='threat-actor--',
        relationship_type__name='targets',
        target_ref__object_id__startswith='identity--',
    )
    if actor_name:
        a = ThreatActor.objects.filter(name=actor_name)
        if a.count() == 1:
            oid = list(a.values_list("object_id", flat=True))
            at = Relationship.objects.filter(
                relationship_type__name="attributed-to",
                target_ref__in=oid,
            )
            oid += list(at.values_list("source_ref",flat=True))    
            sights = sights.filter(sighting_of_ref__in=oid)
            rels = rels.filter(source_ref__in=oid)
    if not tgt:
        tgt = Identity.objects.filter(
            Q(object_id__in=sights.values_list("where_sighted_refs",flat=True))|\
            Q(object_id__in=rels.values_list("target_ref",flat=True)),
        )
    if cnt_by == "sector":
        prop = IndustrySector.objects.all()
    elif cnt_by == "label":
        prop = IdentityLabel.objects.all()
    for p in prop:
        tgt_filtered = []
        if cnt_by == "sector":
            tgt_filtered = tgt.filter(sectors=p)
        elif cnt_by == "label":
            tgt_filtered = tgt.filter(labels=p)
        if tgt_filtered:
            cnt = tgt_filtered.count()
            if cnt:
                item = {
                    "name": p.value,
                    "y": cnt,
                    #"drilldown":{"data": []},
                }
                if drilldown:
                    item["drilldown"] = {"data": []}
                    dd = cnt_actor_from_tgt(tgt_filtered, rels, sights)
                    item["drilldown"] = {
                        "name": "Threat actor targets " + p.value,
                        "data": dd,
                    }
                if not item in dataset:
                    dataset.append(item)
    dataset = sorted(
            dataset,
            key=lambda kv: kv["y"],
            reverse=True
    )
    dataset = json.dumps(dataset,indent=2)
    return dataset

def kill_chain_view(request):
    tas = []
    type = STIXObjectType.objects.filter(
        name__in=[
            "attack-pattern",
            "indicator",
            "malware",
            "tool",
        ]
    )
    zoom = 3
    form = None
    if request.method == "POST":
        if "refresh" in request.POST:
            form = MatrixForm(request.POST)
            if form.is_valid():
                tas = form.cleaned_data["threat_actor"]
                type = form.cleaned_data["type"]
                zoom = form.cleaned_data["zoom"]
    if not form:
            form = MatrixForm()
            form.fields["type"].initial = type.values_list("id",flat=True)
    objs = STIXObject.objects.filter(
        object_type__in=type
    )
    killchain = KillChainPhase.objects.all()
    data =[] 
    for obj in objs:
        o = get_obj_from_id(obj.object_id)
        if o.kill_chain_phases:
            #print(o)
            for kcp in o.kill_chain_phases.all():
                k = {
                    "id": str(kcp.id),
                    "name": kcp.phase_name,
                    "sortIndex": kcp.id,
                }
                #print(k)
                if not k in data:
                    data.append(k)
                p = {
                    "id":o.object_id.object_id,
                    "name": o.name,
                    "parent": str(kcp.id),
                    #"value": 1
                }
                #print(p)
                if not p in data:
                    data.append(p)
                #print(rels)
                #tas = ThreatActor.objects.all()
                #for s in rels.values_list("source_ref", flat=True):
                for ta in tas:
                    rels = Relationship.objects.filter(
                        #source_ref__object_id__startswith="threat-actor",
                        source_ref=ta.object_id,
                        target_ref__object_id=o.object_id.object_id
                    )
                    #ta = get_obj_from_id(s)
                    a = {
                        "id": ta.object_id.object_id,
                        "name": ta.name,
                        "parent": str(o.object_id.object_id),
                        "value": 1,
                        "sortIndex": ta.id,
                    }
                    if rels:
                        a["color"] = "#" + str(hashlib.md5(ta.object_id.object_id.encode("utf8")).hexdigest()[0:6])
                    else:
                        a["color"] = "darkgray"
                        a["name"] = " "
                    if not a in data:
                        data.append(a)
    c = {
        "form":form,
        "zoom":int(zoom),
        "data":data,
    }
    return render(request, 'matrix_viz.html', c)

def ttp_view(request):
    actor = []
    sot = [
        "attack-pattern",
        "indicator",
        "malware",
        "tool",
    ]
    type = STIXObjectType.objects.filter(
        name__in=sot
    )
    form = MatrixForm()
    if request.method == "POST":
        form = MatrixForm(request.POST)
        if form.is_valid():
            actor = form.cleaned_data["threat_actor"]
            type = form.cleaned_data["type"]
            
    objs = STIXObject.objects.filter(
        object_type__in=type
    )
    #a = ThreatActor.objects.all().values_list("object_id", flat=True)
    killchain = KillChainPhase.objects.all().order_by("id")
    data = {}
    for k in killchain:
        data[k.phase_name] = {}
    for obj in objs:
        o = get_obj_from_id(obj.object_id)
        if o.kill_chain_phases:
            #print(o)
            for kcp in o.kill_chain_phases.all():
                rel = Relationship.objects.filter(
                    source_ref__object_id__startswith="campaign",
                    relationship_type__name="uses",
                    target_ref=o.object_id,
                )
                c = rel.values_list("source_ref", flat=True).order_by().distinct()
                rel = Relationship.objects.filter(
                    source_ref__in=c,
                    relationship_type__name="attributed-to",
                    target_ref__object_id__startswith="threat-actor",
                ).values_list("target_ref", flat=True).order_by().distinct()
                if rel:
                    #data[kcp.phase_name][o.name] = rel
                    data[kcp.phase_name][o] = rel
    kdict = {}
    for k,v in data.items():
        kdict[k] = len(v)
    c = {
        "killchain": killchain,
        "kdict": kdict,
        "actor": actor,
        "data":data,
        "form":form,
    }
    return render(request, 'ttp_view.html', c)
