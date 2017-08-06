from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages

import STreifen.models as mymodels
import STreifen.forms as myforms
from ..models import *
from ..forms import *
from .timeline import stix2timeline
#from .sdo import get_related_obj

import re, json, requests
import stix2

def stix2_json(request, id=None):
    objs = []
    if not id:
        for i in STIXObjectID.objects.all():
            o = get_obj_from_id(i)
            if o:
                objs.append(get_obj_from_id(i))
    else:
        obj = STIXObject.objects.get(object_id__object_id=id)
        objs = get_related_obj(obj)
    bundle = stix_bundle(objs)
    j = json.dumps(json.loads(str(bundle)), indent=2)
    return HttpResponse(j,  content_type="application/json")

def stix2type_json(request, type):
    m = get_model_from_type(type)
    a = m.objects.all()
    bundle = stix_bundle(a)
    j = json.dumps(json.loads(str(bundle)), indent=2)
    return HttpResponse(j,  content_type="application/json")

def rel2db(rel, objs):
    src_id = rel["source_ref"]
    src = None
    if src_id in objs:
        src = objs[src_id]
    tgt_id = rel["target_ref"]
    tgt = None
    if tgt_id in objs:
        tgt = objs[tgt_id]
    type = None
    if "relationship_type" in rel:
        type = RelationshipType.objects.get(
            name=rel["relationship_type"]
        )
    dscr = None
    if "description" in rel:
        dscr = rel["description"]
    if src and tgt and type:
        #print(src,type,tgt)
        r, cre = Relationship.objects.get_or_create(
            relationship_type=type,
            source_ref=src.object_id,
            target_ref=tgt.object_id,
            description=dscr,
        )

def sight2db(sight, objs):
    wsrs = []
    if "where_sighted_refs" in sight:
        for w in sight["where_sighted_refs"]:
            sdo = objs[w]
            wsrs.append(sdo)
    sor = None
    if "sighting_of_ref" in sight:
        sid = sight["sighting_of_ref"]
        if sid in objs:
            sor = objs[sid]
    first_seen = None
    if "first_seen" in sight:
        first_seen = sight["first_seen"]
    last_seen = None
    if "last_seen" in sight:
        last_seen = sight["last_seen"]
    if wsrs and sor and first_seen:
        s = Sighting.objcts.filter(
            first_seen=first_seen,
            last_seen=last_seen,
            sighting_of_ref=sor.object_id,
            where_sighted_refs__in=wsrs,
        )
        if not s:
            s = Sighting.objects.create(
                first_seen=first_seen,
                last_seen=last_seen,
                sighting_of_ref=sor.object_id,
            )
            for wsr in wsrs:
                s.where_sighted_refs.add(wsr.object_id)
                s.save()

def stix2_db(obj):
    if "type" in obj:
        type = obj["type"]
        model = get_model_from_type(type)
        if type == 'threat-actor':
            t, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                t.description = obj["description"]
            if "aliases" in obj:
                aliases = obj["aliases"]
                for alias in aliases: 
                    a, cre = ThreatActorAlias.objects.get_or_create(name=alias)
                    t.aliases.add(a)
            if "labels" in obj:
                labels = obj["labels"]
                for label in labels: 
                    l, cre = ThreatActorLabel.objects.get_or_create(value=label)
                    t.labels.add(l)
            t.save()
            return t
        elif type == 'malware':
            m, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                m.description = obj["description"]
            if "labels" in obj:
                labels = obj["labels"]
                for label in labels: 
                    l, cre = MalwareLabel.objects.get_or_create(value=label)
                    m.labels.add(l)
            m.save()
            return m
        elif type == 'tool':
            t, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                t.description = obj["description"]
            if "labels" in obj:
                labels = obj["labels"]
                for label in labels: 
                    l, cre = ToolLabel.objects.get_or_create(value=label)
                    t.labels.add(l)
            t.save()
            return t
        elif type == 'attack-pattern':
            a, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                a.description = obj["description"]
            a.save()
            return a
        elif type == 'vulnerability':
            v, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                v.description = obj["description"]
            v.save()
            return v
        elif type == 'campaign':
            c, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                c.description = obj["description"]
            if "first_seen" in obj:
                c.first_seen = obj["first_seen"]
            if "last_seen" in obj:
                c.last_seen = obj["last_seen"]
            if "aliases" in obj:
                aliases = obj["aliases"]
                for alias in aliases: 
                    a, cre = CampaignAlias.objects.get_or_create(name=alias)
                    c.aliases.add(a)
            c.save()
            return c
        elif type == 'identity':
            i, cre = model.objects.get_or_create(name=obj["name"])
            if "description" in obj:
                i.description = obj["description"]
            if "identity_class" in obj:
                i.identity_class = obj["identity_class"]
            if "sectors" in obj:
                sectors = obj["sectors"]
                for sector in sectors: 
                    s, cre = IndustrySector.objects.get_or_create(value=sector)
                    i.sectors.add(s)
            if "labels" in obj:
                labels = obj["labels"]
                for label in labels: 
                    l, cre = IdentityLabel.objects.get_or_create(value=label)
                    i.labels.add(l)
            i.save()
            return i

def stix_bundle(objs):
    objects = ()
    for obj in objs:
        if obj.object_type.name == 'identity':
            i = stix2.Identity(
                id=obj.object_id.object_id,
                name=obj.name,
                identity_class=obj.identity_class,
                description=obj.description,
                sectors=[str(s.value) for s in obj.sectors.all()],
                labels=[str(l.value) for l in obj.labels.all()],
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
        elif obj.object_type.name == 'vulnerability':
            v = stix2.Vulnerability(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                created=obj.created,
                modified=obj.modified,
            )
            objects += (v,)
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
        elif obj.object_type.name == 'tool':
            t = stix2.Tool(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                labels=[str(l.value) for l in obj.labels.all()],
                created=obj.created,
                modified=obj.modified,
            )
            objects += (t,)
        elif obj.object_type.name == 'indicator':
            pattern = []
            for p in obj.pattern.all():
                pattern.append("(" + p.pattern + ")")
            pattern = "[" + " OR ".join(sorted(pattern)) + "]"
            i = stix2.Indicator(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                labels=[str(l.value) for l in obj.labels.all()],
                pattern=pattern,
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
                aliases=[str(a.name) for a in obj.aliases.all()],
                created=obj.created,
                modified=obj.modified,
                first_seen=obj.first_seen,
                last_seen=obj.last_seen,
            )
            objects += (c,)
        elif obj.object_type.name == 'intrusion-set':
            i = stix2.IntrusionSet(
                id=obj.object_id.object_id,
                name=obj.name,
                description=obj.description,
                aliases=[str(a.name) for a in obj.aliases.all()],
                created=obj.created,
                modified=obj.modified,
                first_seen=obj.first_seen,
                #last_seen=obj.last_seen,
            )
            objects += (i,)
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

def stix_view(request):
    form = InputForm()
    if request.method == "POST":
        #print(request.POST)
        if 'import' in request.POST:
            form = InputForm(request.POST)
            if form.is_valid():
                stix = json.loads(form.cleaned_data["input"])
                if "objects" in stix:
                    sdos = {}
                    rels = {}
                    sights = {}
                    for o in stix["objects"]:
                        if o["type"] == "relationship":
                            rels[o["id"]] = o
                        elif o["type"] == "sighting":
                            sights[o["id"]] = o
                        else:
                            #sdos[o["id"]] = o
                            sdo = stix2_db(o)
                            sdos[o["id"]] = sdo
                    for i in rels:
                        rel2db(rels[i], sdos)
                    for i in sights:
                        sight2db(sights[i], sdos)
        elif 'export' in request.POST:
            objs = []
            for i in STIXObjectID.objects.all():
                o = get_obj_from_id(i)
                if o:
                    objs.append(get_obj_from_id(i))
            bundle = stix_bundle(objs)
            j = json.dumps(json.loads(str(bundle)), indent=2)
            return HttpResponse(j,  content_type="application/json")
        elif 'timeline' in request.POST:
            form = InputForm(request.POST)
            if form.is_valid():
                stix = form.cleaned_data["input"]
                data = stix2timeline(json.loads(stix))
                c = {
                    "items":data["items"],
                    "groups":data["groups"],
                }
                return render(request, 'timeline_viz.html', c)

        elif 'parse_url' in request.POST:
            form = InputForm(request.POST)
            if form.is_valid():
                b = {"objects":[]}
                urls = form.cleaned_data["input"]
                for url in urls.split("\n"):
                    if not re.match("^https?://.+", url):
                        messages.add_message(
                            request,
                            messages.ERROR,
                            'ERROR: Invalid Input -> '+url,
                        )
                    else:
                        res = requests.get(url.strip())
                        if res:
                            j = res.json()
                            if "objects" in j:
                                for o in j["objects"]:
                                    if not o in b["objects"]:
                                        b["objects"].append(o)
                c = {
                    "stix":json.dumps(b, indent=2),
                }
                return render(request, 'stix_viz.html', c)
    c = {
        "form":form,
    }
    return render(request, 'stix_view.html', c)

