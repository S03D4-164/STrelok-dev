from django.shortcuts import render, redirect
from django.db.models import Q

from ..models import *
from ..forms import *
from collections import OrderedDict
import json, hashlib

def chart_view(request):
    data = stats_ati()
    c = {
        "data":data
    }
    return render(request, 'chart.html', c)

def target_stats(rels, id=None):
    ati = rels.filter(
        source_ref__object_id__startswith='threat-actor',
        relationship_type__name='targets',
        target_ref__object_id__startswith='identity',
    )
    if id:
        actor = ThreatActor.objects.get(id=id)
        ati = ati.filter(source_ref__object_id=actor.object_id)
    data = {}
    for a in ati.all():
        act = get_obj_from_id(a.source_ref)
        if not act.name in data:
            data[act.name] = {
                "inner":{},
                "value":0,
            }
        tgt = get_obj_from_id(a.target_ref)
        if tgt:
            data[act.name]["value"] += 1
            label = tgt.labels.all()
            if label:
                if not label[0].value in data[act.name]["inner"]:
                    data[act.name]["inner"][label[0].value] = 1
                else:
                    data[act.name]["inner"][label[0].value] += 1
    for d in data.items():
        d[1]["inner"] = OrderedDict(
            sorted(
                d[1]["inner"].items(),
                key=lambda kv:kv[1],
                reverse=True
            )
        )
    data = OrderedDict(
        sorted(
            data.items(),
            key=lambda kv: kv[1]["value"],
            reverse=True
        )
    )
    return data

def cnt_actor_by_tgt_label(label, relation):
    # identity who has the label
    ids = Identity.objects.filter(
        labels__value=label
    ).values_list('object_id')
    # actor targets identity who has the label
    rel = relation.filter(
        target_ref__in=ids,
    )
    ac = {}
    for r in rel.all():
        a = get_obj_from_id(r.source_ref)
        if not a.name in ac:
            # filter all relation by the actor
            f = relation.filter(
                source_ref=a.object_id,
                target_ref__in=ids
            )
            ac[a.name] = f.count()

    dd = []
    for k, v in ac.items():
        ai = {
            "name": k,
            "y": v,
        }
        dd.append(ai)
    dd = sorted(
        dd,
        key=lambda kv: kv["y"],
        reverse=True
    )
    return dd

def stats_ati():
    dataset = []
    # all actor-targets-identity
    ati = Relationship.objects.filter(
        source_ref__object_id__startswith='threat-actor',
        relationship_type__name='targets',
        target_ref__object_id__startswith='identity',
    )

    # count of target by actor
    actors = ThreatActor.objects.all()
    for actor in actors:
        fati = ati.filter(source_ref=actor.object_id)
        item = {
            "name": actor.name,
            "y": fati.count(),
            "drilldown":{"data": []},
        }

        # count of target category by actor
        cntbt = {} 
        tgts = {}
        for a in fati.all():
            tgt = get_obj_from_id(a.target_ref)
            if tgt:
                l = tgt.labels.all()
                tcat = None
                if l:
                    if l[0].value:
                        tcat = l[0].value
                if tcat:
                    if not tcat in cntbt:
                        cntbt[tcat] = 1
                    elif tcat in cntbt:
                        cntbt[tcat] += 1
                    if not tcat in tgts:
                        tgts[tcat] = [tgt.object_id]
                    elif tcat in tgts:
                        tgts[tcat].append(tgt.object_id)
        d = []
        for tlabel, count in cntbt.items():
            ti = {
                "name": tlabel,
                "y": count,
                #"drilldown":{"data":[]},
            }

            dd = cnt_actor_by_tgt_label(tlabel, ati)
            ti["drilldown"] = {
                "name": "Threat actors targets " + tlabel,
                "data": dd,
            }
            d.append(ti)

        d = sorted(
            d,
            key=lambda kv: kv["y"],
            reverse=True
        )
        item["drilldown"] = {
            "name": "Target catagory of " + actor.name,
            "data": d,
        }

        if item["y"]:
            if not item in dataset:
                dataset.append(item)

    dataset = sorted(
            dataset,
            key=lambda kv: kv["y"],
            reverse=True
    )
    dataset = json.dumps(dataset,indent=2)
    return dataset

def cnt_tgt_by_label():
    dataset = []
    sights = Sighting.objects.filter(
        #where_sighted_refs__object_id__startswith="identity--",
        sighting_of_ref__object_id__startswith="threat-actor--",
    )
    rels = Relationship.objects.filter(
        source_ref__object_id__startswith='threat-actor--',
        relationship_type__name='targets',
        target_ref__object_id__startswith='identity--',
    )
    tgt = Identity.objects.filter(
        Q(id__in=sights.values_list("where_sighted_refs",flat=True))|\
        Q(id__in=rels.values_list("target_ref",flat=True)),
    )
    for l in IdentityLabel.objects.all():
        cnt = tgt.filter(labels=l).count()
        item = {
            "name": l.value,
            "y": cnt,
            "drilldown":{"data": []},
        }
        dd = cnt_actor_by_tgt_label(l, rels)
        item["drilldown"] = {
            "name": "Threat actor targets" + l.value,
            "data": dd,
        }
        if item["y"]:
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
    form = MatrixForm()
    if request.method == "POST":
        form = MatrixForm(request.POST)
        if form.is_valid():
            actor = form.cleaned_data["threat_actor"]
            sot = form.cleaned_data["type"]
            
    type = STIXObjectType.objects.filter(
        name__in=sot
    )
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
