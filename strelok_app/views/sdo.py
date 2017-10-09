from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.apps import apps

from ..models import *
from ..forms import *
from .stix import stix_bundle
from .chart import *

import json
import stix2

from django_otp.decorators import otp_required

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

def get_obs(o):
    t = o.type
    if t.model_name:
        #print(t.model_name)
        m = apps.get_model(t._meta.app_label, t.model_name)
        obs = m.objects.get(id=o.id)
        return obs
    return None

def obs_view(request, id):
    o = ObservableObject.objects.get(id=id)
    dict = {
        id:{
            "type":o.type.name
        } 
    }
    if o.type.model_name:
        m = apps.get_model(o._meta.app_label, o.type.model_name)
        o = m.objects.filter(id=o.id)
        #print(o.values())
        for k, v in o.values()[0].items():
            if not "id" in k and v:
                dict[id][k] = v
        o = o[0]
    if request.POST:
        #print(request.POST)
        if "update" in request.POST:
            form = getform(o.type.name,instance=o, request=request)
            if form.is_valid():
                s = form.save()
                new = form.cleaned_data["new_refs"]
                for line in new.split("\n"):
                    if line:
                        o, p = create_obs_from_line(line)
                        s.resolve_to_refs.add(o)
                        if not p in pattern:
                            pattern.append(p)
                s.save()
                
    form = getform(o.type.name,instance=o)
    objects = []
    rels = []
    value=None
    if hasattr(o, "value"):
        value = o.value
    elif hasattr(o, "name"):
        value = o.name
    ind = Indicator.objects.filter(pattern__pattern__icontains=value)
    for i in ind:
        if not i in objects:
            objects.append(i)
            rel = Relationship.objects.filter(
                source_ref=i.object_id,
                relationship_type=RelationshipType.objects.get(name="indicates")
            )
            for r in rel:
                if not r in rels:
                    rels.append(r)
            for tgt in rel.values_list("target_ref", flat=True):
                t = get_obj_from_id(tgt)
                if not t in objects:
                    objects.append(t)
    c = {
        "obj":o,
        "type":o.type.name,
        "form":form,
        "stix":json.dumps(dict, indent=2),
        "objects":objects,
        "rels":rels,
    }
    return render(request, 'base_view.html', c)

def create_obs_from_line(line):
    o = None
    pattern = None
    type = line.strip().split(":")[0]
    value = ":".join(line.strip().split(":")[1:]).strip()
    t = ObservableObjectType.objects.filter(name=type)
    if t.count() == 1:
        t = t[0]
        if t.model_name:
            m = apps.get_model(t._meta.app_label, t.model_name)
            if t.name == "file":
                o, cre = m.objects.get_or_create(
                    type = t,
                    name = value
                )
                pattern = type + ":name="+ value
            else:
                o, cre = m.objects.get_or_create(
                    type = t,
                    value = value
                )
                pattern = type + ":value=" + value
    return o, pattern

def obs2pattern(observable, new=None, indicator=None, generate=False):
    pattern = []
    obs = []
    if observable:
        for o in observable:
            obs.append(o.id)
            o = get_obs(o)
            p = o.type.name
            if hasattr(o,"name"):
                p += ":name=" + o.name
            elif hasattr(o,"value"):
                p += ":value=" + o.value
            pattern.append(p)
    for line in new.split("\n"):
        if line:
            o, p = create_obs_from_line(line)
            if o:
                obs.append(o.id)
            if p:
                pattern.append(p)
    p = None
    if pattern:
        if indicator:
            p = indicator.pattern
            if p:
                p.observable.clear()
                p.observable.add(*obs)
                if generate:
                    p.pattern = " OR ".join(sorted(pattern))
                    #print(p.pattern)
                p.save()
            else: 
                p = IndicatorPattern.objects.create(
                    pattern = " OR ".join(sorted(pattern))
                )
                p.observable.add(*obs)
                p.save()
                indicator.pattern = p
                indicator.save()
        else:
            p = IndicatorPattern.objects.create(
                pattern = " OR ".join(sorted(pattern))
            )
            p.observable.add(*obs)
            p.save()
    return p

#@otp_required
def sdo_list(request, type):
    sot = STIXObjectType.objects.get(name=type)
    form = getform(type)
    bulkform = InputForm()
    if request.method == "POST":
        if "create" in request.POST:
            form = getform(type, request=request)
            if form.is_valid():
                s = form.save()
                #s = object_form_save(s, form)
                messages.add_message(
                    request, messages.SUCCESS, 'Created -> '+str(s),
                )
            else:
                messages.add_message(
                    request, messages.ERROR, 'Creation Failed',
                )
        elif "create_bulk" in request.POST:
            bulkform = InputForm(request.POST)
            input = None
            if bulkform.is_valid():
                input = bulkform.cleaned_data["input"]
            if input:
                if type == "attack-pattern":
                    kc = None
                    sform = KillChainForm(request.POST)
                    if sform.is_valid():
                        kc = sform.cleaned_data["killchain"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                a, created = AttackPattern.objects.get_or_create(
                                    name=array[0],
                                )
                                a.kill_chain_phases.add(kc)
                                if len(array) >= 2:
                                    a.description = array[1]
                                a.save()
                elif type == "campaign":
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                c, cre = Campaign.objects.get_or_create(name=array[0])
                                ca, cre = CampaignAlias.objects.get_or_create(name=array[0])
                                c.aliases.add(ca)
                                if len(array) >= 2:
                                    for a in array[1:]:
                                        ca, cre = CampaignAlias.objects.get_or_create(name=a)
                                        c.aliases.add(ca)
                                c.save()
                elif type == "course-of-action":
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                c, cre = CourseOfAction.objects.get_or_create(
                                    name=array[0],
                                )
                                if len(array) >= 2:
                                    c.description = array[1]
                                c.save()
                elif type == "identity":
                    ic = None
                    sform = IdentityClassForm(request.POST)
                    if sform.is_valid():
                        ic = sform.cleaned_data["identity_class"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                i, cre = Identity.objects.get_or_create(
                                    name = array[0],
                                    identity_class = ic,
                                )
                                if len(array) >= 2:
                                    if array[1]:
                                        il, cre = IdentityLabel.objects.get_or_create(
                                            value = array[1],
                                        )
                                        i.labels.add(il)
                                if len(array) >= 3:
                                    if array[2]:
                                        i.description = array[2]
                                i.save()
                elif type == "threat-actor":
                    label = None
                    sform = ThreatActorLabelForm(request.POST)
                    if sform.is_valid():
                        label = sform.cleaned_data["labels"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                t, cre = ThreatActor.objects.get_or_create(name=array[0])
                                ta, cre = ThreatActorAlias.objects.get_or_create(name=array[0])
                                t.aliases.add(ta)
                                for l in label:
                                    t.labels.add(l)
                                if len(array) >= 2:
                                    for a in array[1:]:
                                        if a:
                                            ta, cre = ThreatActorAlias.objects.get_or_create(name=a)
                                            t.aliases.add(ta)
                                t.save()
                elif type == "indicator":
                    sform = SelectObservableForm(request.POST)
                    if sform.is_valid():
                        property = sform.cleaned_data["property"]
                        label = sform.cleaned_data["label"]
                        bulk_create_indicator(label,property,input)
                elif type == "malware":
                    label = None
                    sform = MalwareLabelForm(request.POST)
                    if sform.is_valid():
                        label = sform.cleaned_data["labels"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                m, created = Malware.objects.get_or_create(
                                    name=array[0],
                                )
                                for l in label:
                                    m.labels.add(l)
                                if len(array) >= 2:
                                    m.description = array[1]
                                m.save()
                elif type == "tool":
                    label = None
                    sform = ToolLabelForm(request.POST)
                    if sform.is_valid():
                        label = sform.cleaned_data["labels"]
                    for line in input.split("\n"):
                        if line:
                            array = line.strip().split(",")
                            if len(array) >= 1:
                                t, created = Tool.objects.get_or_create(
                                    name=array[0],
                                )
                                for l in label:
                                    t.labels.add(l)
                                if len(array) >= 2:
                                    t.description = array[1]
                                t.save()
    c = {
        "type": type,
        "form": form,
        "bulkform": bulkform,
    }
    if type == "report":
        c["bulkformat"] = "name,label,published,(description)"
    elif type == "attack-pattern":
        c["bulkformat"] = "name,(description)"
        c["sform"] = KillChainForm()
    elif type == "campaign":
        c["bulkformat"] = "name,([alias,..])"
    elif type == "course-of-action":
        c["bulkformat"] = "name,(description)"
    elif type == "threat-actor":
        c["bulkformat"] = "name,([alias,..])"
        c["sform"] = ThreatActorLabelForm()
        c["data"] = stats_ati()
    elif type == "malware":
        c["bulkformat"] = "name,(description)"
        c["sform"] = MalwareLabelForm()
    elif type == "tool":
        c["bulkformat"] = "name,(description)"
        c["sform"] = ToolLabelForm()
    elif type == "identity":
        c["bulkformat"] = "name,(label,description)"
        c["sform"] = IdentityClassForm()
        c["data"] = cnt_tgt_by_label()
    elif type == "indicator":
        c["sform"] = SelectObservableForm()
    return render(request, 'base_list.html', c)

def getform(type, request=None, instance=None, report=None):
    post = None
    if request:
        if request.method == 'POST':
            post = request.POST
    if type == "attack-pattern":
        return AttackPatternForm(post,instance=instance)
    elif type == "campaign":
        return CampaignForm(post,instance=instance)
    elif type == "course-of-action":
        return CourseOfActionForm(post,instance=instance)
    elif type == "identity":
        return IdentityForm(post,instance=instance)
    elif type == "intrusion-set":
        return IntrusionSetForm(post,instance=instance)
    elif type == "malware":
        return MalwareForm(post,instance=instance)
    elif type == "observed-data":
        return ObservedDataForm(post,instance=instance)
    elif type == "report":
        return ReportForm(post,instance=instance)
    elif type == "threat-actor":
        return ThreatActorForm(post,instance=instance)
    elif type == "tool":
        return ToolForm(post,instance=instance)
    elif type == "vulnerability":
        return VulnerabilityForm(post,instance=instance)
    elif type == "indicator":
        return IndicatorForm(post,instance=instance)
    elif type == "domain-name":
        return DomainNameForm(post,instance=instance)
    elif type == "relationship":
        form = RelationshipForm(post,instance=instance)
        if report:
            # exclude SRO
            choices = object_choices(
                ids=report.object_refs.all().exclude(
                Q(object_id__startswith="relationship--")|\
                Q(object_id__startswith="sighting--")|\
                Q(object_id__startswith="observed-data--")|\
                Q(object_id__startswith="report--")
                )
            )
            form.fields["source_ref"].choices = choices
            form.fields["target_ref"].choices = choices
        return form
    elif type == "sighting":
        form = SightingForm(post,instance=instance)
        if report:
            wsr = object_choices(
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
    return None

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
        for od in r.observed_data_refs.all():
            report.object_refs.add(od)
    return report

def get_model_from_type(type):
    name = ""
    t = type.split("--")[0]
    for i in t.split("-"):
        name += i.capitalize()
    m = getattr(mymodels, name)
    return m

"""
def object_form_save(s, form):
    if s.object_type.name == "threat-actor":
        n = form.cleaned_data["new_alias"]
        if n:
            ta, cre = ThreatActorAlias.objects.get_or_create(
                name=n
            )
            s.aliases.add(ta)
            s.save()
    elif s.object_type.name == "indicator":
        observable = form.cleaned_data["observable"]
        if observable:
            p = obs2pattern(observable)
            s.pattern = p
            s.save()
    elif s.object_type.name == "identity":
        l = form.cleaned_data["new_label"]
        if l:
            il, cre = IdentityLabel.objects.get_or_create(
                value=l
            )
            s.labels.add(il)
            s.save()
    elif s.object_type.name == "campaign":
        n = form.cleaned_data["new_alias"]
        if n:
            ca, cre = CampaignAlias.objects.get_or_create(
                name=n
            )
            s.aliases.add(ca)
            s.save()
    return s
"""

def sdo_view(request, id):
    mask = True
    sdo = STIXObject.objects.get(object_id__object_id=id)    
    m = get_model_from_type(id)
    if request.user.is_authenticated():
        mask = False
        sdo = m.objects.get(object_id__object_id=id)
    else:
        if not m == Identity:    
            sdo = m.objects.get(object_id__object_id=id)
    form = getform(id.split("--")[0], instance=sdo)
    objs = get_related_obj(sdo)

    objects = []
    rels = []
    sights = []
    observables = []

    stix = {}
    stix = stix_bundle(objs, mask=mask)
    try:
        pass
        """
        if "objects" in stix:
            for o in stix["objects"]:
                if o.type == "relationship":
                    rels.append(o)
                elif o.type == "sighting":
                    sights.append(o)
                else:
                    objects.append(o)
        """
    except Exception as e:
        stix = str(e.message)

    for o in objs:
        if o.object_type.name == "relationship":
            rels.append(o)
        elif o.object_type.name == "sighting":
            sights.append(o)
        else:
            objects.append(o)

    drs = DefinedRelationship.objects.filter(
        Q(source=sdo.object_type)|\
        Q(target=sdo.object_type)
    )
 
    drform = DefinedRelationshipForm()
    drform.fields["relation"].queryset = drs

    soform = SelectObjectForm()
    if not sdo.object_type.name == "report":
        soform.fields["type"].queryset = STIXObjectType.objects.filter(
            id__in=drs.values("target")
        )

    selected = None
    coform = None

    aoform = AddObjectForm()
    asform = SightingForm()
    if sdo.object_type.name == "identity":
        asform.fields["where_sighted_refs"].initial = sdo
    if not sdo.object_type.name == "report":
        aoform.fields["relation"].queryset = drs
        #aoform.fields["relation"].required = True
        #aoform.fields["relation"].queryset = RelationshipType.objects.filter(
        #  id__in=drs.values("type")
        #)
        #tgt = STIXObject.objects.filter(object_type__in=drs.values("target"))
        aoform.fields["objects"].choices = object_choices(
            #ids=STIXObjectID.objects.filter(id__in=tgt)
            ids=[]
        )

    if request.method == "POST":
        print(request.POST)
        if 'update' in request.POST:
            form = getform(id.split("--")[0],request=request,instance=sdo)
            if form.is_valid():
                s = form.save()
                #s = object_form_save(s, form)
                messages.add_message(request, messages.SUCCESS, 'Updated.')
                return redirect("/stix/"+id)
        elif 'delete' in request.POST:
            name = str(sdo)
            sdo.delete()
            messages.add_message(
                request, messages.SUCCESS,
                'Deleted -> ' + name
            )
            return redirect("/stix/"+id.split("--")[0])
        elif 'detach[]' in request.POST:
            dlist = request.POST.getlist("detach[]")
            if sdo.object_type.name == "report":
                rm = STIXObjectID.objects.filter(object_id__in=dlist)
                rmr = Relationship.objects.filter(
                    object_id__in=sdo.object_refs.all()
                ).filter(
                    Q(source_ref__in=rm)|Q(target_ref__in=rm)
                ).values_list("object_id", flat=True)
                rms = Sighting.objects.filter(
                    object_id__in=sdo.object_refs.all()
                ).filter(
                    Q(sighting_of_ref__in=rm)|Q(where_sighted_refs__in=rm)
                ).values_list("object_id", flat=True)
                sdo.object_refs.remove(*rm, *rmr, *rms)
                sdo.save()
            else:
                for i in STIXObjectID.objects.filter(object_id__in=dlist):
                    #d = get_obj_from_id(i)
                    i.delete()
            messages.add_message(request, messages.SUCCESS, 'Removed.')
            #return redirect("/stix/"+id)
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
                    #print(obform)
                    if obform.is_valid():
                        property = obform.cleaned_data["property"]
                        label = obform.cleaned_data["label"]
                        bulk_create_indicator(label,property,input,src=sdo)
        elif 'select_type' in request.POST:
            sotid = request.POST.get('select_type')
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
                #aoform.fields["objects"].queryset = STIXObjectID.objects.filter(
                #    object_id__startswith=selected.split("--")[0]
                #)
        elif 'select_dr' in request.POST:
            dr = request.POST.get('select_dr')
            #print(dr)
            if dr:
                drs = DefinedRelationship.objects.get(id=dr)
                if drs.source.name == sdo.object_type.name:
                    coform = getform(drs.target.name)
                else:
                    coform = getform(drs.source.name)
        elif 'select_add' in request.POST:
            dr = request.POST.get('select_add')
            if dr:
                drs = DefinedRelationship.objects.get(id=dr)
                t = []
                if drs.source.name == sdo.object_type.name:
                    t = drs.target
                else:
                    t = drs.source
                so = STIXObject.objects.filter(
                    object_type=t,
                )
                aoform.fields["objects"].choices = object_choices(
                    ids=STIXObjectID.objects.filter(
                        id__in=so.values_list("object_id__id",flat=True)
                    )
                )
            """
            rt = request.POST.get('select_rel')
            if rt:
                #r = RelationshipType.objects.get(id=rid)
                drs = DefinedRelationship.objects.filter(
                    type__id=rt,
                )
                t = []
                if drs.filter(source=sdo.object_type):
                    t = STIXObjectType.objects.filter(
                        id__in=drs.values_list("target", flat=True)
                    )
                else:
                    t = STIXObjectType.objects.filter(
                        id__in=drs.values_list("source", flat=True)
                    )
            """
        elif 'create_obj' in request.POST:
            saved = None
            if sdo.object_type.name == "report":
                sotid = request.POST.get('type')
                sot = STIXObjectType.objects.get(id=sotid)
                selected = sot.name
                soform.fields["type"].initial = sotid
                coform = getform(sot.name, request=request)
                if coform.is_valid():
                    saved = coform.save()
                    #if sot.name == "indicator":
                    #saved = object_form_save(saved, coform)
                    report = add_object_refs(sdo, saved.object_id)
                    report.save()
            else:
                dr = request.POST.get('relation')
                if dr:
                    drs = DefinedRelationship.objects.get(id=dr)
                    coform = None
                    src = None
                    tgt = None
                    if drs.source.name == sdo.object_type.name:
                        coform = getform(drs.target.name, request=request)
                        src = sdo.object_id
                    else:
                        coform = getform(drs.source.name, request=request)
                        tgt = sdo.object_id
                    if coform:
                        if coform.is_valid():
                            saved = coform.save()
                            #saved = object_form_save(saved, coform)
                            if saved:
                                if not src:
                                    src = saved.object_id
                                elif not tgt:
                                    tgt = saved.object_id
                                if src and tgt:
                                    Relationship.objects.get_or_create(
                                        source_ref=src,
                                        target_ref=tgt,
                                        relationship_type=drs.type,
                                    )
                            
            if saved:
                messages.add_message(request, messages.SUCCESS,'Created -> ' + str(saved))
            return redirect("/stix/"+id)

        elif 'add_sight' in request.POST:
            asform = SightingForm(request.POST)
            if asform.is_valid():
                s = asform.save()
                """
                ref = asform.cleaned_data["sighting_of_ref"]
                #refs = aoform.cleaned_data["sighting_of_refs"]
                first_seen = asform.cleaned_data["first_seen"]
                last_seen = asform.cleaned_data["last_seen"]
                #for ref in refs:
                if ref:
                    s = Sighting.objects.create(
                        sighting_of_ref=ref,
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                    s.where_sighted_refs.add(sdo)
                    s.save()
                """
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)
        elif 'add_obj' in request.POST:
            aoform = AddObjectForm(request.POST)
            #print(aoform)
            if aoform.is_valid():
                refs = aoform.cleaned_data["objects"]
                rel = aoform.cleaned_data["relation"]
                #print(rel)
                for ref in refs:
                    if sdo.object_type.name == "report":
                        sdo.object_refs.add(ref)
                        r = Relationship.objects.filter(object_id=ref)
                        if r.count() == 1:
                            sdo.object_refs.add(r[0].source_ref, r[0].target_ref)
                        s = Sighting.objects.filter(object_id=ref)
                        if s.count() == 1:
                            sdo.object_refs.add(
                                s[0].sighting_of_ref,
                                *s[0].where_sighted_refs
                        )
                        sdo.save()
                    else:
                        if rel.source == sdo.object_type:
                            Relationship.objects.get_or_create(
                                source_ref=sdo.object_id,
                                relationship_type=rel.type,
                                target_ref=ref,
                            )
                        else:
                            Relationship.objects.get_or_create(
                                target_ref=sdo.object_id,
                                relationship_type=rel.type,
                                source_ref=ref,
                            )
                #report.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Updated.'
                )
                return redirect("/stix/"+id)
        elif 'update_pattern' in request.POST:
            #print(sdo.pattern)
            pform = IndicatorPatternForm(request.POST, instance=sdo.pattern)
            if pform.is_valid():
                #p = pform.save()
                #print(p)
                obs = pform.cleaned_data["observable"]
                new_obs = pform.cleaned_data["new_observable"]
                gen = False
                if "generate_pattern" in request.POST:
                    gen = True
                p = obs2pattern(obs, new=new_obs, indicator=sdo, generate=gen)
                return redirect("/stix/"+id)
    c = {
        "obj": sdo,
        "type": sdo.object_type.name,
        "form": form,
        "soform": soform,
        "aoform": aoform,
        "asform": asform,
        "bform": InputForm(),
        #"selected": selected,
        "coform": coform,
        #"rform": rform,
        "objects": objects,
        "rels": rels,
        "sights": sights,
        "stix":stix,
        "drform": drform,
        "mask":mask,
    }
    if sdo.object_type.name == "indicator":
        c["pform"] = IndicatorPatternForm(instance=sdo.pattern)
    return render(request, 'base_view.html', c)
