from django.shortcuts import render, redirect
from django.db.models import Q
import STreifen.models as mymodels
import STreifen.forms as myforms
from ..models import *
from ..forms import *
from collections import OrderedDict
import json

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
            l = tgt.labels.all()
            tcat = None
            if l[0]:
                if l[0].category:
                    tcat = l[0].category
                elif l[0].value:
                    tcat = l[0].value

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

