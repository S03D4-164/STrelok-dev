from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.db.models import Q

from ..models import *
from ..forms import *
import json

def viz_drs(request):
    c = {"tsform":TypeSelectForm()}
    return render(request, "drs_viz.html", c)

def data_drs(request):
    tsform = TypeSelectForm()
    nodes = []
    edges = []
    drs = None
    if request.method == "POST":
        #print(request.POST)
        tsform = TypeSelectForm(request.POST)
        if tsform.is_valid():
            types = tsform.cleaned_data["types"]
            #print(types)
            rels = tsform.cleaned_data["relation"]
            #print(rels)
            drs = DefinedRelationship.objects.filter(
                Q(source__in=types)|Q(target__in=types),
            ).filter(
                type__in=rels
            )
            
    for dr in drs:
        for sot in (dr.source, dr.target):
            node = {
                'id': sot.id,
                'label': sot.name,
            }
            if not node in nodes:
                nodes.append(node)
        edge = {
            'from': dr.source.id,
            'to': dr.target.id,
            'label': dr.type.name,
        }
        if not edge in edges:
            edges.append(edge)
    dataset = {
        'nodes': nodes,
        'edges': edges,
    }
    return JsonResponse(dataset)
        
